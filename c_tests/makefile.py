import os
import powermake

os.environ["LD_LIBRARY_PATH"] = "../target/performance/:../../boringssl/lib"

def on_build(config: powermake.Config):
    config.add_flags("-Wall", "-Wextra")

    if not config.debug:
        config.add_flags("-flto")

    config.add_shared_libs("crypto", "ssl", "quiche")
    config.add_includedirs("../quiche/include/")

    config.add_ld_flags("-L../target/performance", "-L../../boringssl/lib")

    files = powermake.get_files("**/*.c")
    objects = powermake.compile_files(config, files)

    powermake.link_files(config, powermake.filter_files(objects, "**/server.c.o"), executable_name="client")
    powermake.link_files(config, powermake.filter_files(objects, "**/client.c.o"), executable_name="server")


def on_test(config: powermake.Config, args):
    os.environ["RUST_BACKTRACE"] = "1"
    os.environ["RUST_LOGS"] = "trace"

    if len(args) == 0 or args[0] not in ("client", "server"):
        print("Usage:\n\tpython makefile.py -bvt client ...\nOr:\n\tpython makefile.py -bvt server ...")
        return
    powermake.run_command(config, ["sudo", "LD_LIBRARY_PATH=../target/performance/:../../boringssl/lib", "perf", "record", "-e", "cycles", "-e", "sched:sched_switch", "--switch-events", "--sample-cpu", "-m", "8M", "--aio", "-z", "--call-graph", "dwarf", "-o", f"{args[0]}-perf.data", os.path.join(config.exe_build_directory, args[0]), *args[1:]])

powermake.run("client_server", build_callback=on_build, test_callback=on_test)