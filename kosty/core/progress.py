import sys
import threading
import time
import shutil

class ProgressBar:
    def __init__(self, total: int, description: str = "Processing", width: int = None):
        self.total = total
        self.current = 0
        self.description = description
        self._user_width = width
        self.start_time = time.time()
        self._lock = threading.Lock()
        self._issues_found = 0
        self._stream = sys.stderr
        
    def update(self, increment: int = 1):
        with self._lock:
            self.current += increment
            self._display()
    
    def add_issues(self, count: int):
        """Increment the cumulative issue counter and refresh the display."""
        with self._lock:
            self._issues_found += count
            self._display()
    
    def _display(self):
        if self.total == 0:
            return
            
        percent = min(100, (self.current / self.total) * 100)
        elapsed = time.time() - self.start_time
        elapsed_str = f" {int(elapsed)}s"
        issues_str = f" {self._issues_found} issues" if self._issues_found else ""
        
        # Fixed parts: "Desc: || 100.0% (14/14) 999s 999 issues"
        fixed = f'{self.description}: || {percent:.1f}% ({self.current}/{self.total}){elapsed_str}{issues_str}'
        
        # Auto-size bar to fit terminal width
        try:
            term_width = shutil.get_terminal_size().columns
        except Exception:
            term_width = 80
        
        # Bar width = available space, minimum 10
        bar_width = self._user_width if self._user_width else max(10, term_width - len(fixed) - 2)
        
        filled = int(bar_width * self.current // self.total)
        bar = '█' * filled + '░' * (bar_width - filled)
        
        line = f'{self.description}: |{bar}| {percent:.1f}% ({self.current}/{self.total}){elapsed_str}{issues_str}'
        
        # Hard-truncate to prevent any wrapping
        if len(line) >= term_width:
            line = line[:term_width - 1]
        
        self._stream.write(f'\r\033[2K{line}')
        self._stream.flush()
        
        if self.current >= self.total:
            self._stream.write('\r\033[2K')
            self._stream.flush()

class SpinnerProgress:
    def __init__(self, description: str = "Processing"):
        self.description = description
        self.spinning = False
        self.spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.current_char = 0
        self._thread = None
        
    def start(self):
        self.spinning = True
        self._thread = threading.Thread(target=self._spin)
        self._thread.daemon = True
        self._thread.start()
        
    def stop(self):
        self.spinning = False
        if self._thread:
            self._thread.join()
        sys.stderr.write('\r\033[2K')
        sys.stderr.flush()
        
    def _spin(self):
        while self.spinning:
            char = self.spinner_chars[self.current_char]
            sys.stderr.write(f'\r{char} {self.description}...')
            sys.stderr.flush()
            self.current_char = (self.current_char + 1) % len(self.spinner_chars)
            time.sleep(0.1)