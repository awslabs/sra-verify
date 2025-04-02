"""
Progress tracking for scan operations.
"""
import time
from typing import Optional
from colorama import Fore, Style

class ScanProgress:
    """Progress tracker for scan operations."""
    
    SPINNER = ['/', '-', '\\', '|']
    
    def __init__(self, total_checks: int):
        """
        Initialize the progress tracker.
        
        Args:
            total_checks: The total number of checks to be performed
        
        Raises:
            ValueError: If total_checks is less than or equal to 0
        """
        if total_checks <= 0:
            raise ValueError("total_checks must be greater than 0")
        self.total_checks = total_checks
        self.completed_checks = 0
        self.start_time = time.time()
        self.current_service: Optional[str] = None
        self.spinner_index = 0
        self.last_print_time = 0
        self.print_interval = 0.1  # Update display every 0.1 seconds
    
    @property
    def progress(self) -> float:
        """
        Calculate the progress percentage.
        
        Returns:
            Progress percentage
        """
        return (self.completed_checks / self.total_checks * 100)
    
    @property
    def duration(self) -> str:
        """
        Calculate the elapsed time in minutes:seconds format.
        
        Returns:
            Elapsed time string
        """
        elapsed = int(time.time() - self.start_time)
        minutes = elapsed // 60
        seconds = elapsed % 60
        return f"{minutes}:{seconds:02d}"
    
    def update(self, service: str):
        """
        Update the current service being scanned.
        
        Args:
            service: Service name
        """
        self.current_service = service
        self.print_progress()
        
    def increment(self):
        """Increment the completed checks counter."""
        self.completed_checks += 1
        self.spinner_index = (self.spinner_index + 1) % len(self.SPINNER)
        self.print_progress()
        
    def print_progress(self):
        """Print the current progress status with rate limiting."""
        current_time = time.time()
        # Only update display if enough time has passed since last update
        if current_time - self.last_print_time >= self.print_interval:
            self._do_print()
            self.last_print_time = current_time

    def _do_print(self):
        """Actually perform the progress printing."""
        spinner = self.SPINNER[self.spinner_index]
        
        # Calculate the width of the progress bar (50 characters)
        bar_width = 50
        filled_length = int(self.progress / 100 * bar_width)
        bar = '=' * filled_length + ' ' * (bar_width - filled_length)
        
        # Format the progress bar with current status
        print(f"{Fore.BLUE}\r-> Scanning {self.current_service} service {Style.RESET_ALL} |{bar}| {spinner} "
              f"{self.completed_checks}/{self.total_checks} "
              f"[{self.progress:.0f}%] in {self.duration}", 
              end="", flush=True)
    
    def finish(self):
        """Complete the progress display with a newline."""
        print()  # Print newline to finish the progress display
