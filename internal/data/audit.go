package data

import (
	"context"
	"iwut-auth-center/internal/biz"
	"sync"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type auditRepo struct {
	data *Data
	log  *log.Helper

	auditCh      chan *Audit
	auditWG      sync.WaitGroup
	auditWorkers int
	closeOnce    sync.Once
	mu           sync.RWMutex // protect send vs close on auditCh
}

// NewAuditRepo returns the audit repo and a cleanup function. The cleanup should be
// called during application shutdown to drain the queue and stop workers.
func NewAuditRepo(data *Data, logger log.Logger) (biz.AuditRepo, func(), error) {
	r := &auditRepo{
		data:         data,
		log:          log.NewHelper(log.With(logger, "module", "audit/repo")),
		auditCh:      make(chan *Audit, 512),
		auditWG:      sync.WaitGroup{},
		auditWorkers: 2,
	}
	for i := 0; i < r.auditWorkers; i++ {
		r.auditWG.Add(1)
		go r.auditWorker(i)
	}

	cleanup := func() {
		// ensure close is idempotent
		r.Close()
	}

	return r, cleanup, nil
}

func (r *auditRepo) auditWorker(idx int) {
	defer r.auditWG.Done()
	// worker 起始日志
	r.log.Infof("audit worker %d started", idx)
	// 可用带重试的写法或直接写
	for a := range r.auditCh {
		// 每次写入使用独立短超时时间，避免单个慢写阻塞队列消费
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = ctx
		attempts := 0
		for {
			err := r.data.db.WithContext(ctx).Create(a).Error
			if err == nil {
				// success
				break
			}
			attempts++
			if attempts >= 2 {
				// record and drop after retries
				r.log.Errorf("insert audit failed after %d attempts: %v, audit=%+v", attempts, err, a)
				break
			}
			// simple backoff then retry once
			time.Sleep(100 * time.Millisecond)
		}
		cancel()
	}
}

// Close gracefully shuts down the audit workers and drains the queue.
func (r *auditRepo) Close() {
	r.closeOnce.Do(func() {
		// stop accepting new audits and wait workers to finish
		r.mu.Lock()
		close(r.auditCh)
		r.mu.Unlock()
		r.auditWG.Wait()
		// optional: log completion
		r.log.Infof("audit repo closed, workers finished")
	})
}

// Audit is the key for context value storage
// id clientId userId ip ua finishAt resultCode errorMessage
type Audit struct {
	ID         string    `gorm:"primaryKey;column:id;type:char(36)"`  // UUID v4 string
	TraceID    string    `gorm:"column:trace_id;type:char(32);index"` // trace id as 32 hex chars
	ClientID   string    `gorm:"column:client_id;type:varchar(128)"`
	UserID     string    `gorm:"column:user_id;type:varchar(64)"`
	IP         string    `gorm:"column:ip;type:varchar(45)"`
	UA         string    `gorm:"column:ua;type:varchar(512)"`
	Function   string    `gorm:"column:function;type:varchar(128)"`
	FinishAt   time.Time `gorm:"column:finish_at"`
	ResultCode int       `gorm:"column:result_code"`
	Message    string    `gorm:"column:message;type:text"`
}

// BeforeCreate hook will set a UUID for the ID if not already set
func (a *Audit) BeforeCreate(_ *gorm.DB) (err error) {
	if a.ID == "" {
		a.ID = uuid.NewString()
	}
	return nil
}

func (r *auditRepo) InsertAuditForRequest(ctx context.Context, traceID, clientID, userID, ip, function, ua string, finishAt time.Time, resultCode int, errMsg string) {
	_ = ctx
	a := &Audit{
		TraceID:    traceID,
		ClientID:   clientID,
		UserID:     userID,
		Function:   function,
		IP:         ip,
		UA:         ua,
		FinishAt:   finishAt,
		ResultCode: resultCode,
		Message:    errMsg,
	}

	// 非阻塞入队：保持 API 快速返回；队列已满则丢弃并记录告警
	r.mu.RLock()
	defer r.mu.RUnlock()
	select {
	case r.auditCh <- a:
		// 已入队，异步写入，返回 nil 表示正常（你也可以选择返回 nil 始终）
	default:
		// 队列满：记录警告，但不要阻塞或影响调用方
		r.log.Warnf("audit channel full, dropping audit: trace=%s client=%s", traceID, clientID)
	}
}
