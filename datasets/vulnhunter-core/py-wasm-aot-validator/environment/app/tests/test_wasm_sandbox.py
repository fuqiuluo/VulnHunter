import unittest

from wasm_sandbox import (
    FuncType,
    HostFunc,
    Linker,
    ModuleBuilder,
    TrapError,
    ValType,
    ValidationError,
    decode_module,
    validate_module,
)


class WasmSandboxSmokeTests(unittest.TestCase):
    def test_iterative_fibonacci_and_structured_loops(self) -> None:
        mb = ModuleBuilder()
        t_i32_to_i32 = mb.add_type([ValType.I32], [ValType.I32])
        mb.add_func(
            t_i32_to_i32,
            [(3, ValType.I32)],  # local 1 = a, local 2 = b, local 3 = i
            [
                ("i32.const", 0),
                ("local.set", 1),
                ("i32.const", 1),
                ("local.set", 2),
                ("i32.const", 0),
                ("local.set", 3),
                ("block", None),
                ("loop", None),
                ("local.get", 3),
                ("local.get", 0),
                ("i32.ge_s",),
                ("br_if", 1),
                ("local.get", 1),
                ("local.get", 2),
                ("i32.add",),
                ("local.get", 2),
                ("local.set", 1),
                ("local.set", 2),
                ("local.get", 3),
                ("i32.const", 1),
                ("i32.add",),
                ("local.set", 3),
                ("br", 0),
                ("end",),
                ("end",),
                ("local.get", 1),
            ],
            export_as="fib",
        )
        mod = decode_module(mb.to_bytes())
        inst = Linker().instantiate(mod)
        self.assertEqual(inst.invoke("fib", [0]), 0)
        self.assertEqual(inst.invoke("fib", [1]), 1)
        self.assertEqual(inst.invoke("fib", [10]), 55)

    def test_br_table_switch_and_valid_polymorphic_unreachable(self) -> None:
        mb = ModuleBuilder()
        t_sig = mb.add_type([ValType.I32], [ValType.I32])
        mb.add_func(
            t_sig,
            [],
            [
                ("block", ValType.I32),
                ("block", None),
                ("block", None),
                ("block", None),
                ("local.get", 0),
                ("br_table", [0, 1], 2),
                ("end",),
                ("i32.const", 100),
                ("br", 2),
                ("end",),
                ("i32.const", 200),
                ("br", 1),
                ("end",),
                ("i32.const", 300),
                ("br", 0),
                # Polymorphic unreachable tail inside the block itself
                ("i32.add",),
                ("end",),
            ],
            export_as="dispatch",
        )
        inst = Linker().instantiate(decode_module(mb.to_bytes()))
        self.assertEqual(inst.invoke("dispatch", [0]), 100)
        self.assertEqual(inst.invoke("dispatch", [1]), 200)

    def test_linear_memory_and_call_indirect_dispatch(self) -> None:
        mb = ModuleBuilder()
        t_op = mb.add_type([ValType.I32, ValType.I32], [ValType.I32])
        t_run = mb.add_type([ValType.I32, ValType.I32, ValType.I32], [ValType.I32])

        f_add = mb.add_func(t_op, [], [("local.get", 0), ("local.get", 1), ("i32.add",)])
        f_mul = mb.add_func(t_op, [], [("local.get", 0), ("local.get", 1), ("i32.mul",)])
        mb.add_table(4)
        mb.add_memory(1, 2)
        mb.add_elem(0, [("i32.const", 0)], [f_add, f_mul])
        mb.add_data(0, [("i32.const", 16)], (7).to_bytes(4, "little"))

        mb.add_func(
            t_run,
            [],
            [
                ("local.get", 0),
                ("i32.const", 16),
                ("i32.load", 2, 0),
                ("i32.add",),
                ("local.get", 1),
                ("local.get", 2),
                ("call_indirect", t_op, 0),
            ],
            export_as="compute",
        )
        inst = Linker().instantiate(decode_module(mb.to_bytes()))
        self.assertEqual(inst.invoke("compute", [3, 5, 0]), 15)  # (3+7) + 5
        self.assertEqual(inst.invoke("compute", [3, 5, 1]), 50)  # (3+7) * 5
        with self.assertRaises(TrapError):
            inst.invoke("compute", [3, 5, 2])  # null slot 2

    def test_multi_module_host_import_and_type_mismatch_rejection(self) -> None:
        mb_bad = ModuleBuilder()
        t_void = mb_bad.add_type([], [ValType.I32])
        mb_bad.add_func(t_void, [], [("i64.const", 9)])
        with self.assertRaises(ValidationError):
            validate_module(decode_module(mb_bad.to_bytes()))

        mb = ModuleBuilder()
        t_fn = mb.add_type([ValType.I32], [ValType.I32])
        mb.add_import_func("env", "triple", t_fn)
        mb.add_func(t_fn, [], [("local.get", 0), ("call", 0), ("i32.const", 1), ("i32.add",)], export_as="run")
        linker = Linker()
        linker.define("env", "triple", HostFunc(FuncType((ValType.I32,), (ValType.I32,)), lambda x: (x * 3) & 0xFFFFFFFF))
        inst = linker.instantiate(decode_module(mb.to_bytes()))
        self.assertEqual(inst.invoke("run", [10]), 31)


if __name__ == "__main__":
    unittest.main()
