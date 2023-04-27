from typing import List, Tuple

from slither.core.declarations import Function, FunctionContract, Contract
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.solidity_types.function_type import FunctionType

class Code(AbstractDetector):
    """
    Unprotected function detector
    """

    ARGUMENT = "code"
    HELP = "Functions that are not used"
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#dead-code"

    WIKI_TITLE = "Dead-code"
    WIKI_DESCRIPTION = "Functions that are not used."

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Contract{
    function dead_code() internal() {}
}

'dead_code' is not used in the contract, and make the code's review more difficult."""
    # endregion wiki_exploit_scenario
    WIKI_RECOMMENDATION = "Remove unused functions."

    def _detect(self):

        results = []

        functions_used = set()
        for contract in self.compilation_unit.contracts_derived:
            all_functionss_called = [
                f.all_internal_calls() for f in contract.functions_entry_points
            ]
            all_functions_called = [item for sublist in all_functionss_called for item in sublist]
            functions_used |= {
                f.canonical_name for f in all_functions_called if isinstance(f, Function)
            }
            all_libss_called = [f.all_library_calls() for f in contract.functions_entry_points]
            all_libs_called: List[Tuple[Contract, Function]] = [
                item for sublist in all_libss_called for item in sublist
            ]
            functions_used |= {
                lib[1].canonical_name for lib in all_libs_called if isinstance(lib, tuple)
            }

            # Check for functions assigned to function pointers
            for f in contract.functions:
                for v in f.state_variables_written:
                    if v.type and isinstance(v.type, FunctionType) and v.expression:
                        if v.expression.type == 'function_type':
                            functions_used.add(v.expression.referenced_declaration.canonical_name)

            # Check for function pointers in contract level
            for v in contract.variables:
                if v.type and isinstance(v.type, FunctionType) and v.expression:
                    if v.expression.type == 'function_type':
                        functions_used.add(v.expression.referenced_declaration.canonical_name)

            # Check for function pointers assigned to state variables
            for sv in contract.state_variables:
                if sv.type and isinstance(sv.type, FunctionType) and sv.expression:
                    if sv.expression.type == 'function_type':
                        functions_used.add(sv.expression.referenced_declaration.canonical_name)

            # NEW: Check for function pointers assigned to function declarations
            for f in contract.functions:
                if f.is_implemented and f.expression:
                    function_pointer = f.expression
                    if function_pointer.type == 'function_type':
                        functions_used.add(function_pointer.referenced_declaration.canonical_name)


        for function in sorted(self.compilation_unit.functions, key=lambda x: x.canonical_name):
            if (
                function.visibility in ["public", "external"]
                or function.is_constructor
                or function.is_fallback
                or function.is_constructor_variables
            ):
                continue
            if function.canonical_name in functions_used:
                continue
            if isinstance(function, FunctionContract) and (
                function.contract_declarer.is_from_dependency()
            ):
                continue
            # Continue if the function is not implemented because it means the contract is abstract
            if not function.is_implemented:
                continue
            info = [function, " is never used and should be removed\n"]
            res = self.generate_result(info)
            results.append(res)

        return results

