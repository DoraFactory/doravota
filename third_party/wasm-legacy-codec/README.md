# Legacy Wasm wire codec

Only five generated protobuf files and interface/Amino registration are retained from the pinned organization fork; checksums and license are included. There is no Wasm keeper, VM, engine, query server or active transaction service registration. `msgservice.RegisterMsgServiceDesc` registers codec metadata, not a BaseApp handler. Generated gRPC stubs are inert and never registered by the application.

`compat.go` supplies minimal legacy interfaces, raw JSON handling and proposal formatting. Wasm-specific authorization validation and execution always return ErrRetired. Existing records are readable and can expire through SDK authz. No grants, proposal deposits or contract balances are deleted or moved at retirement.

Do not import wasmd or wasmvm into this package. When adding a historical type, preserve its original protobuf name and schema, test binary/JSON/nested Any decoding, and verify that the application's message router still has no Wasm handler.
