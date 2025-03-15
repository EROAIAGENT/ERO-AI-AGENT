# core/agent/coding_agent/ast_validator.py
from __future__ import annotations
import ast
import logging
import hashlib
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path
from dataclasses import dataclass
import libcst as cst
import semgrep
from pydantic import BaseModel, ValidationError
from loguru import logger
from libcst.metadata import MetadataWrapper, PositionProvider

@dataclass(frozen=True)
class ValidationResult:
    is_valid: bool
    error_messages: List[str]
    security_violations: List[str]
    type_issues: List[str]
    ast_hash: str
    metrics: Dict[str, float]

class ASTValidationError(Exception):
    """Critical failure in AST parsing/validation pipeline"""

class BaseASTValidator:
    """Abstract base class for AST validation rules"""
    def __init__(self, config: Dict):
        self.config = config
        self._compile_rules()

    def _compile_rules(self) -> None:
        """Precompile validation patterns for performance"""
        raise NotImplementedError

    def validate(self, tree: ast.AST) -> List[str]:
        """Execute validation rules against AST"""
        raise NotImplementedError

class SecurityValidator(BaseASTValidator):
    """Static analysis for security vulnerabilities"""
    def _compile_rules(self) -> None:
        self.rules = [
            (ast.Call, self._check_dangerous_functions),
            (ast.Import, self._check_restricted_imports),
            (ast.ImportFrom, self._check_restricted_imports),
            (ast.Assign, self._check_unsafe_assignments)
        ]

    def validate(self, tree: ast.AST) -> List[str]:
        violations = []
        for node in ast.walk(tree):
            for node_type, check_fn in self.rules:
                if isinstance(node, node_type):
                    violations.extend(check_fn(node))
        return violations

    def _check_dangerous_functions(self, node: ast.Call) -> List[str]:
        dangerous_funcs = {'eval', 'exec', 'open', 'os.system'}
        if isinstance(node.func, ast.Name) and node.func.id in dangerous_funcs:
            return [f"Dangerous function call detected: {node.func.id}"]
        return []

    def _check_restricted_imports(self, node: ast.Import|ast.ImportFrom) -> List[str]:
        restricted = {'pickle', 'subprocess', 'ctypes'}
        for alias in node.names:
            if alias.name.split('.')[0] in restricted:
                return [f"Restricted import detected: {alias.name}"]
        return []

    def _check_unsafe_assignments(self, node: ast.Assign) -> List[str]:
        if any(isinstance(target, ast.Attribute) for target in node.targets):
            return ["Potential unsafe attribute assignment"]
        return []

class TypeSafetyValidator(BaseASTValidator):
    """Static type consistency checker"""
    def _compile_rules(self) -> None:
        self.type_map: Dict[str, str] = {}
        self.rules = [
            (ast.FunctionDef, self._check_function_signatures),
            (ast.AnnAssign, self._check_annotations),
            (ast.Assign, self._check_type_consistency)
        ]

    def validate(self, tree: ast.AST) -> List[str]:
        self.type_map.clear()
        issues = []
        for node in ast.walk(tree):
            for node_type, check_fn in self.rules:
                if isinstance(node, node_type):
                    issues.extend(check_fn(node))
        return issues

    def _check_function_signatures(self, node: ast.FunctionDef) -> List[str]:
        # Implementation details for type checking
        return []

class ASTValidator:
    """Enterprise-grade AST validation pipeline"""
    def __init__(self, security_level: int = 3):
        self.validators = [
            SecurityValidator(config={"level": security_level}),
            TypeSafetyValidator(config={}),
        ]
        self.cache: Dict[str, ValidationResult] = {}
        self.metric_store = ValidationMetrics()

    def validate_code(self, code: str) -> ValidationResult:
        """Full validation pipeline with caching and metrics"""
        cache_key = self._generate_cache_key(code)
        if cached := self.cache.get(cache_key):
            return cached

        try:
            parsed_ast = self._parse_ast(code)
            libcst_tree = self._parse_libcst(code)
        except SyntaxError as e:
            logger.error(f"Syntax validation failed: {e}")
            raise ASTValidationError(f"Invalid syntax: {e}") from e

        validation_result = self._execute_validation(parsed_ast, libcst_tree, code)
        self._store_metrics(validation_result)
        self.cache[cache_key] = validation_result
        return validation_result

    def _parse_ast(self, code: str) -> ast.AST:
        """Parse code with fallback to libcst for error recovery"""
        try:
            return ast.parse(code)
        except SyntaxError:
            return cst.parse_module(code).ast()

    def _parse_libcst(self, code: str) -> cst.Module:
        """Parse with position metadata for detailed reporting"""
        return MetadataWrapper(cst.parse_module(code))

    def _execute_validation(self, ast_tree: ast.AST, cst_tree: cst.Module, code: str) -> ValidationResult:
        """Run all validation rules with metric tracking"""
        errors = []
        security_violations = []
        type_issues = []

        for validator in self.validators:
            start = time.monotonic()
            try:
                if isinstance(validator, SecurityValidator):
                    security_violations = validator.validate(ast_tree)
                elif isinstance(validator, TypeSafetyValidator):
                    type_issues = validator.validate(ast_tree)
            except Exception as e:
                errors.append(f"Validator {type(validator).__name__} failed: {str(e)}")
            finally:
                self.metric_store.record(
                    validator_type=type(validator).__name__,
                    duration=time.monotonic() - start,
                    code_length=len(code)
                )

        return ValidationResult(
            is_valid=not bool(errors + security_violations + type_issues),
            error_messages=errors,
            security_violations=security_violations,
            type_issues=type_issues,
            ast_hash=self._generate_ast_hash(ast_tree),
            metrics=self.metric_store.current_metrics()
        )

    def _generate_cache_key(self, code: str) -> str:
        """Generate content-aware cache key"""
        return hashlib.sha3_256(code.encode()).hexdigest()

    def _generate_ast_hash(self, tree: ast.AST) -> str:
        """Create deterministic hash of AST structure"""
        return hashlib.md5(ast.dump(tree).encode()).hexdigest()

class ValidationMetrics:
    """Performance tracking for validation operations"""
    def __init__(self):
        self.metrics = {
            "total_validations": 0,
            "avg_validation_time": 0.0,
            "security_check_time": 0.0,
            "lines_validated": 0
        }

    def record(self, validator_type: str, duration: float, code_length: int) -> None:
        self.metrics["total_validations"] += 1
        self.metrics["avg_validation_time"] = (
            (self.metrics["avg_validation_time"] * (self.metrics["total_validations"] - 1) + duration) 
            / self.metrics["total_validations"]
        )
        if validator_type == "SecurityValidator":
            self.metrics["security_check_time"] += duration
        self.metrics["lines_validated"] += code_length // 40  # Approximate line count

    def current_metrics(self) -> Dict[str, float]:
        return self.metrics.copy()

# Example Usage
validator = ASTValidator(security_level=3)

def validate_generated_code(code: str) -> bool:
    try:
        result = validator.validate_code(code)
        if not result.is_valid:
            logger.error(f"Validation failed: {result.error_messages}")
            return False
        return True
    except ASTValidationError as e:
        logger.critical(f"AST validation crashed: {str(e)}")
        return False

# Unit Test Example
def test_ast_validation():
    sample_code = """
import os
def risky_function():
    eval('os.system("rm -rf /")')
    """
    
    result = validator.validate_code(sample_code)
    assert not result.is_valid
    assert "Dangerous function call detected: eval" in result.security_violations
    assert "Restricted import detected: os" in result.security_violations
