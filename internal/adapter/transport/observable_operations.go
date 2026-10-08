package transport

import (
	"sort"

	kgrpc "github.com/go-kratos/kratos/v2/transport/grpc"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
)

func registerObservableOperations(register func(string, []string), httpServer *khttp.Server, grpcServer *kgrpc.Server) {
	if register == nil {
		return
	}
	httpOperations := map[string]struct{}{}
	_ = httpServer.WalkRoute(func(route khttp.RouteInfo) error {
		httpOperations[route.Path] = struct{}{}
		return nil
	})
	register("http", sortedOperationKeys(httpOperations))

	grpcOperations := map[string]struct{}{}
	for service, info := range grpcServer.GetServiceInfo() {
		for _, method := range info.Methods {
			grpcOperations["/"+service+"/"+method.Name] = struct{}{}
		}
	}
	register("grpc", sortedOperationKeys(grpcOperations))
}

func sortedOperationKeys(operations map[string]struct{}) []string {
	keys := make([]string, 0, len(operations))
	for operation := range operations {
		keys = append(keys, operation)
	}
	sort.Strings(keys)
	return keys
}
