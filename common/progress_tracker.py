"""
Progress tracking system for long-running operations with real-time updates.
Supports Server-Sent Events (SSE) streaming for web clients.
"""

import time
import json
import logging
import queue
import threading
from typing import Optional, Dict, Any, List
from datetime import datetime
from common.utils import generate_timestamp


class ProgressTracker:
    """
    Progress tracker for operations with real-time streaming capabilities.

    Tracks operation progress and can stream updates via SSE to web clients.
    """

    def __init__(self, operation_id: str, total_steps: int, progress_queue: Optional[queue.Queue] = None):
        """
        Initialize progress tracker.

        Args:
            operation_id: Unique identifier for this operation
            total_steps: Total number of steps expected for this operation
            progress_queue: Queue for sending progress events (for SSE streaming)
        """
        self.operation_id = operation_id
        self.total_steps = total_steps
        self.current_step = 0
        self.progress_queue = progress_queue
        self.start_time = time.time()
        self.logger = logging.getLogger(__name__)
        self.substeps: List[Dict[str, Any]] = []
        self.is_complete = False

        # Send initial progress event
        self._send_progress_event(
            step_name="Operation initialized",
            percentage=0,
            log_level="info",
            status="running"
        )

    def update(self, step_name: str, percentage: Optional[int] = None,
               log_level: str = 'info', details: Optional[str] = None,
               increment_step: bool = True) -> None:
        """
        Update progress with a new step.

        Args:
            step_name: Description of current step
            percentage: Progress percentage (0-100), calculated automatically if None
            log_level: Log level ('info', 'warning', 'error', 'success')
            details: Additional details about the step
            increment_step: Whether to increment the current step counter
        """
        if self.is_complete:
            self.logger.warning(f"Attempted to update completed operation {self.operation_id}")
            return

        if increment_step:
            self.current_step += 1

        # Calculate percentage if not provided
        if percentage is None:
            percentage = min(int((self.current_step / self.total_steps) * 100), 99)

        # Log the progress
        self.logger.info(f"Operation {self.operation_id}: Step {self.current_step}/{self.total_steps} - {step_name}")
        if details:
            self.logger.info(f"Details: {details}")

        # Send progress event
        self._send_progress_event(
            step_name=step_name,
            percentage=percentage,
            log_level=log_level,
            details=details,
            status="running"
        )

    def add_substep(self, description: str, status: str = 'running',
                   log_level: str = 'info') -> None:
        """
        Add a substep without incrementing main progress.

        Args:
            description: Description of the substep
            status: Status of substep ('running', 'completed', 'error')
            log_level: Log level for the substep
        """
        if self.is_complete:
            return

        substep = {
            "description": description,
            "status": status,
            "log_level": log_level,
            "timestamp": generate_timestamp()
        }

        self.substeps.append(substep)
        self.logger.info(f"Substep: {description}")

        # Send substep event
        self._send_progress_event(
            step_name=f"└─ {description}",
            percentage=None,  # Don't change percentage for substeps
            log_level=log_level,
            details=None,
            status="running",
            is_substep=True
        )

    def clear_substeps(self) -> None:
        """
        Clear all accumulated substeps.

        This is useful when you want to start fresh with substeps for a new operation phase
        without carrying over substeps from previous phases.
        """
        self.substeps.clear()
        self.logger.debug(f"Cleared substeps for operation {self.operation_id}")

    def complete(self, success: bool = True, message: str = "Operation completed", result_data: Dict = None) -> None:
        """
        Mark operation as complete.

        Args:
            success: Whether operation completed successfully
            message: Completion message
            result_data: Optional result data to include in completion event
        """
        if self.is_complete:
            return

        self.is_complete = True
        elapsed_time = time.time() - self.start_time

        status = "completed" if success else "error"
        log_level = "success" if success else "error"

        self.logger.info(f"Operation {self.operation_id} {status} in {elapsed_time:.2f}s: {message}")

        # Send completion event with result data
        self._send_progress_event(
            step_name=message,
            percentage=100,
            log_level=log_level,
            details=f"Completed in {elapsed_time:.2f} seconds",
            status=status,
            result_data=result_data
        )

        # Send final termination event
        if self.progress_queue:
            try:
                self.progress_queue.put({
                    "type": "complete",
                    "operation_id": self.operation_id,
                    "success": success,
                    "elapsed_time": elapsed_time,
                    "result_data": result_data
                }, timeout=1)
            except queue.Full:
                self.logger.warning(f"Progress queue full, dropped completion event for {self.operation_id}")

    def error(self, error_message: str, details: Optional[str] = None, result_data: Dict = None) -> None:
        """
        Mark operation as failed with error.

        Args:
            error_message: Error description
            details: Additional error details
            result_data: Optional result data to include in error event
        """
        self.complete(success=False, message=f"Error: {error_message}", result_data=result_data)
        if details:
            self.add_substep(f"Error details: {details}", status="error", log_level="error")

    def _send_progress_event(self, step_name: str, percentage: Optional[int],
                           log_level: str, details: Optional[str] = None,
                           status: str = "running", is_substep: bool = False,
                           result_data: Optional[Dict] = None) -> None:
        """
        Send progress event to queue for SSE streaming.

        Args:
            step_name: Current step description
            percentage: Progress percentage
            log_level: Log level
            details: Additional details
            status: Operation status
            is_substep: Whether this is a substep event
            result_data: Optional result data for completion events
        """
        if not self.progress_queue:
            return

        event_data = {
            "type": "progress",
            "operation_id": self.operation_id,
            "timestamp": generate_timestamp(),
            "step_number": self.current_step,
            "total_steps": self.total_steps,
            "step_name": step_name,
            "log_level": log_level,
            "status": status,
            "is_substep": is_substep
        }

        # Only include percentage for main steps
        if percentage is not None:
            event_data["percentage"] = percentage

        if details:
            event_data["details"] = details

        # Include result data for completion events
        if result_data:
            event_data["result_data"] = result_data

        if self.substeps and not is_substep:
            event_data["substeps"] = self.substeps.copy()

        try:
            self.progress_queue.put(event_data, timeout=1)
        except queue.Full:
            self.logger.warning(f"Progress queue full, dropped event for {self.operation_id}")


class ProgressManager:
    """
    Manages multiple concurrent operations and their progress tracking.
    Thread-safe operation management for SSE streaming.
    """

    def __init__(self):
        self.active_operations: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()
        self.logger = logging.getLogger(__name__)

        # Cleanup thread for abandoned operations
        self.cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
        self.cleanup_thread.start()

    def create_operation(self, operation_id: str, total_steps: int) -> ProgressTracker:
        """
        Create a new operation with progress tracking.

        Args:
            operation_id: Unique identifier for the operation
            total_steps: Expected number of steps

        Returns:
            ProgressTracker instance for the operation
        """
        progress_queue = queue.Queue(maxsize=100)  # Limit queue size
        tracker = ProgressTracker(operation_id, total_steps, progress_queue)

        with self.lock:
            self.active_operations[operation_id] = {
                "tracker": tracker,
                "queue": progress_queue,
                "created_at": time.time(),
                "last_activity": time.time()
            }

        self.logger.info(f"Created operation {operation_id} with {total_steps} steps")
        return tracker

    def get_operation_queue(self, operation_id: str) -> Optional[queue.Queue]:
        """
        Get the progress queue for an operation.

        Args:
            operation_id: Operation identifier

        Returns:
            Progress queue or None if operation doesn't exist
        """
        with self.lock:
            operation = self.active_operations.get(operation_id)
            if operation:
                operation["last_activity"] = time.time()
                return operation["queue"]
        return None

    def complete_operation(self, operation_id: str) -> None:
        """
        Mark an operation as complete and schedule for cleanup.

        Args:
            operation_id: Operation identifier
        """
        with self.lock:
            if operation_id in self.active_operations:
                self.active_operations[operation_id]["completed_at"] = time.time()
                self.logger.info(f"Marked operation {operation_id} as complete")

    def remove_operation(self, operation_id: str) -> None:
        """
        Remove an operation from tracking.

        Args:
            operation_id: Operation identifier
        """
        with self.lock:
            if operation_id in self.active_operations:
                del self.active_operations[operation_id]
                self.logger.info(f"Removed operation {operation_id}")

    def get_active_operations(self) -> List[str]:
        """Get list of currently active operation IDs."""
        with self.lock:
            return list(self.active_operations.keys())

    def _cleanup_worker(self) -> None:
        """
        Background worker to clean up old/abandoned operations.
        Runs every 60 seconds and removes operations older than 5 minutes.
        """
        while True:
            try:
                time.sleep(60)  # Check every minute
                current_time = time.time()
                cleanup_threshold = 300  # 5 minutes

                with self.lock:
                    operations_to_remove = []

                    for operation_id, operation_data in self.active_operations.items():
                        # Remove if completed more than 30 seconds ago
                        if "completed_at" in operation_data:
                            if current_time - operation_data["completed_at"] > 30:
                                operations_to_remove.append(operation_id)
                        # Remove if no activity for more than 5 minutes
                        elif current_time - operation_data["last_activity"] > cleanup_threshold:
                            operations_to_remove.append(operation_id)

                    for operation_id in operations_to_remove:
                        del self.active_operations[operation_id]
                        self.logger.info(f"Cleaned up abandoned operation {operation_id}")

            except Exception as e:
                self.logger.error(f"Error in progress cleanup worker: {e}")


# Global progress manager instance
progress_manager = ProgressManager()
