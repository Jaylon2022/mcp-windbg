from .server import serve, serve_http

def main():
    """MCP WinDbg Server - Windows crash dump analysis functionality for MCP"""
    import argparse
    import asyncio

    parser = argparse.ArgumentParser(
        description="Give a model the ability to analyze Windows crash dumps with WinDbg/CDB"
    )
    parser.add_argument("--cdb-path", type=str, help="Custom path to cdb.exe (user-mode debugger)")
    parser.add_argument("--kd-path", type=str, help="Custom path to kd.exe (kernel-mode debugger, used for kernel debugging sessions)")
    parser.add_argument("--symbols-path", type=str, help="Custom symbols path")
    parser.add_argument("--sysinternals-path", type=str, help="Path to Sysinternals Suite directory (e.g. E:\\SysinternalsSuite)")
    parser.add_argument("--xperf-path", type=str, help="Custom path to xperf.exe (Windows Performance Toolkit, used for ETL trace analysis)")
    parser.add_argument("--gpuview-path", type=str, help="Path to GPUView.exe directory (Windows Performance Toolkit GPUView, used for GPU ETL trace analysis)")
    parser.add_argument("--timeout", type=int, default=30, help="Command timeout in seconds")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")

    # Transport options
    parser.add_argument(
        "--transport",
        type=str,
        choices=["stdio", "streamable-http"],
        default="stdio",
        help="Transport protocol to use (default: stdio)"
    )
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host to bind HTTP server to (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind HTTP server to (default: 8000)")

    args = parser.parse_args()

    if args.transport == "stdio":
        asyncio.run(serve(
            cdb_path=args.cdb_path,
            kd_path=args.kd_path,
            symbols_path=args.symbols_path,
            sysinternals_path=args.sysinternals_path,
            xperf_path=args.xperf_path,
            gpuview_path=args.gpuview_path,
            timeout=args.timeout,
            verbose=args.verbose
        ))
    else:
        asyncio.run(serve_http(
            host=args.host,
            port=args.port,
            cdb_path=args.cdb_path,
            kd_path=args.kd_path,
            symbols_path=args.symbols_path,
            sysinternals_path=args.sysinternals_path,
            xperf_path=args.xperf_path,
            gpuview_path=args.gpuview_path,
            timeout=args.timeout,
            verbose=args.verbose
        ))


if __name__ == "__main__":
    main()
