import sys
from typing import Optional
import threading
import time

class ProgressBar:
    def __init__(self, total: int, description: str = "Processing", width: int = 50):
        self.total = total
        self.current = 0
        self.description = description
        self.width = width
        self.start_time = time.time()
        self._lock = threading.Lock()
        
    def update(self, increment: int = 1):
        with self._lock:
            self.current += increment
            self._display()
    
    def set_description(self, description: str):
        with self._lock:
            self.description = description
            self._display()
    
    def _display(self):
        if self.total == 0:
            return
            
        percent = min(100, (self.current / self.total) * 100)
        filled = int(self.width * self.current // self.total)
        bar = '█' * filled + '░' * (self.width - filled)
        
        elapsed = time.time() - self.start_time
        if self.current > 0:
            eta = (elapsed / self.current) * (self.total - self.current)
            eta_str = f" ETA: {int(eta)}s" if eta > 1 else ""
        else:
            eta_str = ""
        
        # Clear line and write progress
        sys.stdout.write('\r' + ' ' * 100 + '\r')
        sys.stdout.write(f'{self.description}: |{bar}| {percent:.1f}% ({self.current}/{self.total}){eta_str}')
        sys.stdout.flush()
        
        if self.current >= self.total:
            sys.stdout.write('\r' + ' ' * 100 + '\r')
            sys.stdout.flush()

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
        sys.stdout.write('\r' + ' ' * 100 + '\r')
        sys.stdout.flush()
        
    def _spin(self):
        while self.spinning:
            char = self.spinner_chars[self.current_char]
            sys.stdout.write(f'\r{char} {self.description}...')
            sys.stdout.flush()
            self.current_char = (self.current_char + 1) % len(self.spinner_chars)
            time.sleep(0.1)