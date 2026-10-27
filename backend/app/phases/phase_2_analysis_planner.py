"""
Phase 2: LLM #1 Tree Mapper - Repository Analysis Planning

This module implements Phase 2 of the SentinelAI pipeline:
- Input: tree.json
- Output: analysis_plan.json
- LLM #1 performs repository understanding and planning

Phase 2 focuses on:
1. Repository tree understanding
2. Framework/language identification
3. Important file selection
4. Security-sensitive area identification
5. Analysis plan generation
6. Tool and check requirement determination
"""

import json
import os
from pathlib import Path
from typing import Dict, Any
from app.schemas.scan_request import ScanRequest
from app.services.analysis_planner import AnalysisPlanner
from app.core.logger import get_logger

logger = get_logger(__name__)
class Phase2AnalysisPlanner:
    """Implements Phase 2: LLM #1 Tree Mapper functionality."""

    def __init__(self, scan_id: str, scan_request: ScanRequest):
        self.scan_id = scan_id
        self.scan_request = scan_request
        self.workspace_path = Path(__file__).resolve().parents[2] / "runtime" / "workspaces" / scan_id

    def execute_phase_2(self) -> Dict[str, Any]:
        """Execute Phase 2: LLM #1 Tree Mapper."""
        logger.info(f"Starting Phase 2: LLM #1 Tree Mapper for scan {self.scan_id}")

        # Step 1: Load tree.json from workspace
        tree_data = self._load_tree_json()
        logger.info(f"Loaded tree.json with {len(tree_data.get('files', []))} files")

        # Step 2: Generate analysis plan using AnalysisPlanner
        analysis_planner = AnalysisPlanner(self.scan_request, tree_data)
        analysis_plan = analysis_planner.generate_analysis_plan()

        # Step 3: Save analysis plan
        success = analysis_planner.save_analysis_plan(self.scan_id)
        if not success:
            raise Exception(f"Failed to save analysis plan for scan {self.scan_id}")

        # Step 4: Log completion
        self._log_phase_completion(analysis_plan)

        logger.info(f"Phase 2 completed successfully for scan {self.scan_id}")
        return analysis_plan

    def _load_tree_json(self) -> Dict[str, Any]:
        """Load tree.json from scan workspace."""
        tree_path = self.workspace_path / "tree.json"

        if not tree_path.exists():
            raise Exception(f"tree.json not found in workspace {self.scan_id}")

        try:
            with open(tree_path, 'r', encoding='utf-8') as f:
                tree_data = json.load(f)

            logger.info(f"Successfully loaded tree.json from {tree_path}")
            return tree_data

        except json.JSONDecodeError as e:
            raise Exception(f"Invalid JSON in tree.json: {e}")
        except Exception as e:
            raise Exception(f"Error loading tree.json: {e}")

    def _log_phase_completion(self, analysis_plan: Dict[str, Any]) -> None:
        """Log Phase 2 completion details."""
        logger.info("Phase 2 - LLM #1 Tree Mapper - Completion Summary:")
        logger.info(f"  Scan ID: {analysis_plan.get('scan_id')}")
        logger.info(f"  Repository Type: {analysis_plan.get('repository_info', {}).get('name', 'Unknown')}")
        logger.info(f"  Technology Stack: {', '.join(analysis_plan.get('stack', []))}")
        logger.info(f"  Languages Detected: {list(analysis_plan.get('languages', {}).keys())}")
        logger.info(f"  Frameworks Identified: {len(analysis_plan.get('frameworks', []))}")
        logger.info(f"  Important Files Selected: {len(analysis_plan.get('important_files', []))}")
        logger.info(f"  Security Areas Identified: {len(analysis_plan.get('security_sensitive_areas', []))}")
        logger.info(f"  Tools Required: {len(analysis_plan.get('required_tools', []))}")
        logger.info(f"  Deterministic Checks: {len(analysis_plan.get('required_deterministic_checks', []))}")
        logger.info(f"  AST Checks: {len(analysis_plan.get('required_ast_checks', []))}")
        logger.info(f"  Vulnerability Queries: {len(analysis_plan.get('vulnerability_knowledge_queries', []))}")
        logger.info(f"  Compliance Queries: {len(analysis_plan.get('compliance_queries', []))}")
        logger.info(f"  Overall Confidence: {analysis_plan.get('confidence', {}).get('technical_stack_confidence', 0):.2f}")

    def run_on_real_repository(self, scan_id: str, scan_request: ScanRequest) -> Dict[str, Any]:
        """Run Phase 2 analysis on a real repository."""
        logger.info(f"Running Phase 2 analysis on real repository: {scan_request.get_repository_identifier()}")

        try:
            # Initialize Phase 2 analyzer
            phase2_analyzer = Phase2AnalysisPlanner(scan_id, scan_request)

            # Execute Phase 2
            analysis_plan = phase2_analyzer.execute_phase_2()

            return {
                "scan_id": scan_id,
                "status": "completed",
                "phase": "Phase 2 - LLM #1 Tree Mapper",
                "analysis_plan": analysis_plan,
                "message": "Phase 2 analysis completed successfully",
                "next_phase": "Phase 3 - Deterministic and AST Analysis",
            }

        except Exception as e:
            logger.error(f"Phase 2 analysis failed: {e}")
            raise Exception(f"Phase 2 analysis failed for scan {scan_id}: {e}")

    def validate_analysis_plan(self, scan_id: str) -> bool:
        """Validate that analysis_plan.json was created correctly."""
        analysis_path = self.workspace_path / "analysis_plan.json"

        if not analysis_path.exists():
            logger.error(f"analysis_plan.json not found in workspace {scan_id}")
            return False

        try:
            with open(analysis_path, 'r', encoding='utf-8') as f:
                analysis_plan = json.load(f)

            # Validate required fields
            required_fields = [
                "scan_id", "timestamp", "repository_info", "stack",
                "languages", "frameworks", "confidence",
                "important_files", "security_sensitive_areas",
                "dependency_queries", "vulnerability_knowledge_queries",
                "compliance_queries", "required_tools",
                "required_deterministic_checks", "required_ast_checks",
                "decision_reasons", "estimated_scope", "prioritization"
            ]

            missing_fields = []
            for field in required_fields:
                if field not in analysis_plan:
                    missing_fields.append(field)

            if missing_fields:
                logger.error(f"analysis_plan.json missing required fields: {missing_fields}")
                return False

            logger.info(f"analysis_plan.json validation successful for scan {scan_id}")
            return True

        except Exception as e:
            logger.error(f"Error validating analysis_plan.json: {e}")
            return False
def execute_phase_2_analysis(scan_id: str, scan_request: ScanRequest) -> Dict[str, Any]:
    """Main entry point for Phase 2 execution."""
    logger.info(f"=== PHASE 2 EXECUTION START ===")
    logger.info(f"Scan ID: {scan_id}")
    logger.info(f"Repository: {scan_request.get_repository_identifier()}")
    logger.info(f"Source Type: {scan_request.source_type}")
    logger.info(f"Branch: {scan_request.branch}")

    try:
        # Run Phase 2 analysis
        result = Phase2AnalysisPlanner.run_on_real_repository(scan_id, scan_request)

        logger.info(f"=== PHASE 2 EXECUTION COMPLETED ===")
        logger.info(f"Result: {result['status']}")
        logger.info(f"Next Phase: {result['next_phase']}")

        return result

    except Exception as e:
        logger.error(f"Phase 2 execution failed: {e}")
        raise Exception(f"Phase 2 execution failed: {e}")
if __name__ == "__main__":
    # Example usage
    print("Phase 2 - LLM #1 Tree Mapper")
    print("=" * 50)

    # Test with a real scan (you would provide actual scan_id and scan_request)
    test_scan_id = "TEST-20240101-123456-abcdef12"
    print(f"Example: execute_phase_2_analysis('{test_scan_id}', scan_request)")
    print("=" * 50)
    print("This script implements Phase 2 of the SentinelAI pipeline.")
    print("Input: tree.json from repository workspace")
    print("Output: analysis_plan.json with complete analysis plan")
    print("=" * 50)
