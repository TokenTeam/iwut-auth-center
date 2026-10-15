package mongo

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
)

type fixtureSchemaSetup func(context.Context, *drivermongo.Database) error

// Pools are process-local and separated by the ordered, named schema setup
// functions. Each lease exclusively owns a database, even for parallel tests.
var fixturePools = struct {
	sync.Mutex
	pools map[string]*reusableFixturePool
}{pools: make(map[string]*reusableFixturePool)}

type reusableFixturePool struct {
	sync.Mutex
	client *drivermongo.Client
	idle   []*reusableFixture
	all    map[string]*drivermongo.Database
}

type reusableFixture struct {
	database *drivermongo.Database
	schema   []fixtureCollectionSchema
	seeds    map[string][]bson.Raw
}

type fixtureCollectionSchema struct {
	Name    string
	Type    string
	Options string
	Indexes []string
}

func TestMain(m *testing.M) {
	code := m.Run()
	for _, pool := range fixturePools.pools {
		for _, db := range pool.all {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			err := db.Drop(ctx)
			cancel()
			if err != nil {
				fmt.Fprintln(os.Stderr, "drop reusable integration database:", err)
				code = 1
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := pool.client.Disconnect(ctx)
		cancel()
		if err != nil {
			fmt.Fprintln(os.Stderr, "disconnect reusable integration client:", err)
			code = 1
		}
	}
	os.Exit(code)
}

// Only direct, parameter-free Ensure* functions belong in a schema profile.
// Explicit migration/index upgrade tests keep using integrationDatabase instead.
func reusableIntegrationDatabase(t *testing.T, setups ...fixtureSchemaSetup) *drivermongo.Database {
	t.Helper()
	uri := os.Getenv(mongoIntegrationURIEnvironment)
	if uri == "" {
		t.Skip("MONGODB_INTEGRATION_URI is required")
	}
	if len(setups) == 0 {
		t.Fatal("a reusable fixture requires explicit schema setup")
	}
	names := make([]string, len(setups))
	for i, setup := range setups {
		if setup == nil {
			t.Fatal("nil fixture schema setup")
		}
		names[i] = runtime.FuncForPC(reflect.ValueOf(setup).Pointer()).Name()
		if strings.Contains(names[i], ".func") {
			t.Fatal("schema profiles require named functions, not closures")
		}
	}
	key := uri + "\x00" + strings.Join(names, "\x00")
	fixturePools.Lock()
	pool := fixturePools.pools[key]
	if pool == nil {
		client, err := NewClient(uri)
		if err != nil {
			fixturePools.Unlock()
			t.Fatal(err)
		}
		pool = &reusableFixturePool{client: client, all: make(map[string]*drivermongo.Database)}
		fixturePools.pools[key] = pool
	}
	fixturePools.Unlock()
	pool.Lock()
	var fixture *reusableFixture
	if n := len(pool.idle); n > 0 {
		fixture = pool.idle[n-1]
		pool.idle = pool.idle[:n-1]
	}
	pool.Unlock()
	var db *drivermongo.Database
	if fixture != nil {
		db = fixture.database
	} else {
		db = pool.client.Database("iwut_auth_fixture_" + strings.ReplaceAll(uuid.NewString(), "-", ""))
		pool.Lock()
		pool.all[db.Name()] = db
		pool.Unlock()
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		returned := false
		defer func() {
			if !returned {
				dropCtx, dropCancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer dropCancel()
				if err := db.Drop(dropCtx); err != nil {
					t.Errorf("discard reusable database: %v", err)
					return
				}
				pool.Lock()
				delete(pool.all, db.Name())
				pool.Unlock()
			}
		}()
		if t.Failed() || fixture == nil {
			return
		}
		schema, err := fixtureSchema(ctx, db)
		if err != nil {
			t.Errorf("inspect reusable schema: %v", err)
			return
		}
		if !reflect.DeepEqual(schema, fixture.schema) {
			return
		}
		if err := fixture.reset(ctx); err != nil {
			t.Errorf("reset reusable database: %v", err)
			return
		}
		pool.Lock()
		pool.idle = append(pool.idle, fixture)
		pool.Unlock()
		returned = true
	})
	if fixture == nil {
		for _, setup := range setups {
			if err := setup(t.Context(), db); err != nil {
				t.Fatalf("initialize reusable schema: %v", err)
			}
		}
		var err error
		fixture, err = snapshotIntegrationFixture(t.Context(), db)
		if err != nil {
			t.Fatalf("snapshot reusable database: %v", err)
		}
	}
	return db
}

func fixtureSchema(ctx context.Context, database *drivermongo.Database) ([]fixtureCollectionSchema, error) {
	specs, err := database.ListCollectionSpecifications(ctx, bson.D{})
	if err != nil {
		return nil, err
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].Name < specs[j].Name })
	result := make([]fixtureCollectionSchema, 0, len(specs))
	for _, spec := range specs {
		// Canonical Extended JSON retains BSON types and meaningful field order.
		options, err := fixtureDocument(spec.Options)
		if err != nil {
			return nil, err
		}
		cursor, err := database.Collection(spec.Name).Indexes().List(ctx)
		if err != nil {
			return nil, err
		}
		var indexes []bson.Raw
		if err := cursor.All(ctx, &indexes); err != nil {
			return nil, err
		}
		entry := fixtureCollectionSchema{Name: spec.Name, Type: spec.Type, Options: options}
		for _, index := range indexes {
			canonical, err := fixtureDocument(index)
			if err != nil {
				return nil, err
			}
			entry.Indexes = append(entry.Indexes, canonical)
		}
		sort.Strings(entry.Indexes)
		result = append(result, entry)
	}
	return result, nil
}

func fixtureDocument(raw bson.Raw) (string, error) {
	encoded, err := bson.MarshalExtJSON(raw, true, false)
	return string(encoded), err
}

func snapshotIntegrationFixture(ctx context.Context, database *drivermongo.Database) (*reusableFixture, error) {
	schema, err := fixtureSchema(ctx, database)
	if err != nil {
		return nil, err
	}
	fixture := &reusableFixture{database: database, schema: schema, seeds: make(map[string][]bson.Raw)}
	for _, collection := range schema {
		cursor, err := database.Collection(collection.Name).Find(ctx, bson.D{})
		if err != nil {
			return nil, err
		}
		var seeds []bson.Raw
		if err := cursor.All(ctx, &seeds); err != nil {
			return nil, err
		}
		fixture.seeds[collection.Name] = seeds
	}
	return fixture, nil
}

func (fixture *reusableFixture) reset(ctx context.Context) error {
	for _, collection := range fixture.schema {
		coll := fixture.database.Collection(collection.Name)
		if _, err := coll.DeleteMany(ctx, bson.D{}); err != nil {
			return fmt.Errorf("clear %s: %w", collection.Name, err)
		}
		seeds := fixture.seeds[collection.Name]
		if len(seeds) > 0 {
			documents := make([]any, len(seeds))
			for i := range seeds {
				documents[i] = seeds[i]
			}
			if _, err := coll.InsertMany(ctx, documents); err != nil {
				return fmt.Errorf("restore %s seeds: %w", collection.Name, err)
			}
		}
	}
	return nil
}

func ensureFixtureGuardSchema(ctx context.Context, db *drivermongo.Database) error {
	if err := EnsurePrincipalSchema(ctx, db); err != nil {
		return err
	}
	return EnsureAuthenticationSchema(ctx, db)
}

func TestReusableFixtureRestoresSeedAndExclusiveOwnership(t *testing.T) {
	var name string
	var seed bson.Raw
	t.Run("dirty lease", func(t *testing.T) {
		db := reusableIntegrationDatabase(t, ensureFixtureGuardSchema)
		name = db.Name()
		var err error
		seed, err = db.Collection(AuthenticationRuntimeCollection).FindOne(t.Context(), bson.M{"_id": "authentication"}).Raw()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Collection(PrincipalCollection).InsertOne(t.Context(), bson.M{"authId": "fixture-owner"}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Collection(AuthenticationRuntimeCollection).DeleteMany(t.Context(), bson.D{}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("restored lease", func(t *testing.T) {
		db := reusableIntegrationDatabase(t, ensureFixtureGuardSchema)
		if db.Name() != name {
			t.Fatal("unchanged schema was not reused")
		}
		n, err := db.Collection(PrincipalCollection).CountDocuments(t.Context(), bson.D{})
		if err != nil || n != 0 {
			t.Fatal("previous owner's data survived", n, err)
		}
		got, err := db.Collection(AuthenticationRuntimeCollection).FindOne(t.Context(), bson.M{"_id": "authentication"}).Raw()
		if err != nil || !reflect.DeepEqual(seed, got) {
			t.Fatal("authentication fence seed was not restored exactly", err)
		}
		other := reusableIntegrationDatabase(t, ensureFixtureGuardSchema)
		if db.Name() == other.Name() {
			t.Fatal("simultaneous leases share a database")
		}
		profile := reusableIntegrationDatabase(t, EnsureAuthenticationSchema)
		if db.Name() == profile.Name() {
			t.Fatal("different schema profiles share a database")
		}
	})
}

func TestReusableFixtureDiscardsSchemaChanges(t *testing.T) {
	for _, kind := range []string{"validator", "index", "collection"} {
		t.Run(kind, func(t *testing.T) {
			var name string
			t.Run("mutate", func(t *testing.T) {
				db := reusableIntegrationDatabase(t, ensureFixtureGuardSchema)
				name = db.Name()
				var err error
				switch kind {
				case "validator":
					err = db.RunCommand(t.Context(), bson.D{{Key: "collMod", Value: PrincipalCollection}, {Key: "validator", Value: bson.M{"authId": "forbidden"}}}).Err()
				case "index":
					err = db.Collection(PrincipalCollection).Indexes().DropOne(t.Context(), "auth_id_unique")
				case "collection":
					err = db.CreateCollection(t.Context(), "unexpected_fixture_collection")
				}
				if err != nil {
					t.Fatal(err)
				}
			})
			t.Run("clean lease", func(t *testing.T) {
				db := reusableIntegrationDatabase(t, ensureFixtureGuardSchema)
				if db.Name() == name {
					t.Fatal("changed schema was reused")
				}
			})
		})
	}
}

func TestReusableFixtureParallelLeases(t *testing.T) {
	var active sync.Map
	for i := 0; i < 4; i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			db := reusableIntegrationDatabase(t, ensureFixtureGuardSchema)
			if _, exists := active.LoadOrStore(db.Name(), true); exists {
				t.Fatal("parallel leases share a database")
			}
			t.Cleanup(func() { active.Delete(db.Name()) })
			if _, err := db.Collection(PrincipalCollection).InsertOne(t.Context(), bson.M{"authId": "same-owner"}); err != nil {
				t.Fatal(err)
			}
			n, err := db.Collection(PrincipalCollection).CountDocuments(t.Context(), bson.D{})
			if err != nil || n != 1 {
				t.Fatal("parallel data leaked", n, err)
			}
		})
	}
}

func TestFixtureSchemaFingerprintPreservesBSONTypesAndIndexOrder(t *testing.T) {
	fingerprint := func(value bson.D) string {
		raw, err := bson.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		result, err := fixtureDocument(raw)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	if fingerprint(bson.D{{Key: "value", Value: int32(1)}}) == fingerprint(bson.D{{Key: "value", Value: int64(1)}}) {
		t.Fatal("BSON numeric types collapsed")
	}
	if fingerprint(bson.D{{Key: "key", Value: bson.D{{Key: "a", Value: 1}, {Key: "b", Value: 1}}}}) == fingerprint(bson.D{{Key: "key", Value: bson.D{{Key: "b", Value: 1}, {Key: "a", Value: 1}}}}) {
		t.Fatal("compound index field order collapsed")
	}
}
