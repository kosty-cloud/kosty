"""Report persistence layer — local filesystem and S3.

StorageManager handles the actual I/O after the reporter has serialized
findings to a string. Keeping this separate from the reporter means the
reporter doesn't need to know anything about S3 paths or network shares.

S3 uploads use AES256 server-side encryption by default. The validation
step (validate_save_location) runs before the scan starts so we fail fast
rather than completing a 10-minute scan only to discover we can't write
the output.

Network share support (UNC paths, /mnt/, /Volumes/) uses asyncio timeouts
to avoid hanging indefinitely on unreachable mounts.
"""

import asyncio
import boto3
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from .exceptions import SaveLocationError


def confine_local_path(file_path: str, allow_outside_cwd: bool = False) -> Path:
    """Resolve a local --save-to path and confine it to the current directory.

    resolve() only normalizes the path (collapsing '..' and symlinks); it does
    not by itself prevent writing outside an intended root. Confinement is
    enforced here: unless allow_outside_cwd is set, a destination that resolves
    outside the current working directory raises SaveLocationError. s3:// paths
    are handled elsewhere and never reach this function.
    """
    resolved = Path(file_path).resolve()
    if allow_outside_cwd:
        return resolved
    cwd = Path.cwd().resolve()
    if resolved != cwd and cwd not in resolved.parents:
        raise SaveLocationError(
            f"Refusing to write outside the current directory: {resolved}. "
            f"Pass --allow-outside-cwd (or set save_to_allow_outside: true) to override."
        )
    return resolved


class StorageManager:
    """Writes report files to local disk, network shares, or S3.

    All public methods are async because S3 operations are I/O-bound and
    we want to keep the CLI responsive during large org-wide scans.
    """

    def __init__(self):
        self.s3_client = None

    async def validate_save_location(self, save_to: str, allow_outside_cwd: bool = False) -> bool:
        """Probe the target location before the scan starts.

        For S3: does a put + delete of a tiny test object to confirm
        we have write access. For local paths: confirms the path stays
        inside the current directory (unless allow_outside_cwd is set),
        then creates the directory and writes a throwaway file.
        """
        if not save_to:
            return True
        if save_to.startswith('s3://'):
            return await self._validate_s3_access(save_to)
        return await self._validate_local_path(save_to, allow_outside_cwd=allow_outside_cwd)

    async def _validate_s3_access(self, s3_path: str) -> bool:
        """Confirm s3:PutObject access by writing and deleting a test object."""
        try:
            bucket, key_prefix = self._parse_s3_path(s3_path)
            self.s3_client = boto3.client('s3')
            test_key = f"{key_prefix}/kosty_access_test.txt" if key_prefix else "kosty_access_test.txt"

            loop = asyncio.get_running_loop()
            with ThreadPoolExecutor() as executor:
                await loop.run_in_executor(
                    executor,
                    lambda: self.s3_client.put_object(
                        Bucket=bucket, Key=test_key,
                        Body=b'test', ServerSideEncryption='AES256'
                    )
                )
                await loop.run_in_executor(
                    executor,
                    lambda: self.s3_client.delete_object(Bucket=bucket, Key=test_key)
                )
            return True

        except Exception as e:
            error_msg = str(e)
            print("\n❌ S3 access validation failed:")
            if "NoSuchBucket" in error_msg:
                print(f"   • Bucket '{bucket}' does not exist")
            elif "AccessDenied" in error_msg:
                print(f"   • Access denied to bucket '{bucket}'")
                print("   • Ensure you have s3:PutObject permissions")
            elif "InvalidBucketName" in error_msg:
                print(f"   • Invalid bucket name '{bucket}'")
            else:
                print(f"   • {error_msg}")
            print("\n💡 S3 path format: s3://bucket-name/optional/path/")
            return False

    async def _validate_local_path(self, file_path: str, allow_outside_cwd: bool = False) -> bool:
        """Confirm we can create files at the target path.

        Network shares get a 10-second timeout — a hung NFS mount would
        otherwise block the entire CLI indefinitely.
        """
        try:
            is_network = self._is_network_path(file_path)
            if is_network:
                print(f"🌐 Detected network path: {file_path}")
                print("   • Testing network connectivity...")

            # resolve() normalizes the path; confinement to the working
            # directory is enforced separately by confine_local_path().
            resolved = confine_local_path(file_path, allow_outside_cwd=allow_outside_cwd)
            path = resolved

            if file_path.endswith('/') or file_path.endswith('\\'):
                directory = path
                test_file = directory / "kosty_access_test.txt"
            else:
                directory = path.parent
                test_file = path.with_suffix('.test')

            if is_network:
                await self._create_directory_with_timeout(directory)
                await self._write_test_file_with_timeout(test_file)
                print("   ✅ Network path accessible")
            else:
                directory.mkdir(parents=True, exist_ok=True)
                test_file.write_text('test')
                test_file.unlink()

            return True

        except SaveLocationError as e:
            print(f"\n❌ Path access validation failed:")
            print(f"   • {e}")
            return False
        except PermissionError:
            print(f"\n❌ Path access validation failed:")
            print(f"   • Permission denied to write to '{file_path}'")
            if self._is_network_path(file_path):
                print("   • Check network share permissions and credentials")
            else:
                print("   • Check file system permissions")
            return False
        except TimeoutError:
            print(f"\n❌ Network path access timeout:")
            print(f"   • Network path '{file_path}' is not accessible")
            print("   • Check network connectivity and share availability")
            return False
        except Exception as e:
            print(f"\n❌ Path access validation failed:")
            print(f"   • {e}")
            if self._is_network_path(file_path):
                print("   • Ensure network share is mounted and accessible")
            return False

    def _is_network_path(self, file_path: str) -> bool:
        """Return True for UNC paths and common Unix network mount points."""
        if file_path.startswith('\\\\') or file_path.startswith('//'):
            return True
        return any(file_path.startswith(p) for p in ('/mnt/', '/media/', '/net/', '/Volumes/'))

    async def _create_directory_with_timeout(self, directory: Path, timeout: int = 10):
        loop = asyncio.get_running_loop()
        with ThreadPoolExecutor() as executor:
            await asyncio.wait_for(
                loop.run_in_executor(executor, lambda: directory.mkdir(parents=True, exist_ok=True)),
                timeout=timeout
            )

    async def _write_test_file_with_timeout(self, test_file: Path, timeout: int = 10):
        loop = asyncio.get_running_loop()
        with ThreadPoolExecutor() as executor:
            await asyncio.wait_for(
                loop.run_in_executor(executor, lambda: test_file.write_text('test')),
                timeout=timeout
            )
            await asyncio.wait_for(
                loop.run_in_executor(executor, lambda: test_file.unlink()),
                timeout=timeout
            )

    async def save_file(self, content: str, filename: str, save_to: str,
                        file_format: str, allow_outside_cwd: bool = False) -> str:
        """Persist content to the target location and return the final path/URL."""
        if not save_to:
            with open(filename, 'w') as f:
                f.write(content)
            return filename

        if save_to.startswith('s3://'):
            return await self._save_to_s3(content, filename, save_to, file_format)
        return await self._save_to_local_path(content, filename, save_to, file_format,
                                               allow_outside_cwd=allow_outside_cwd)

    async def _save_to_s3(self, content: str, filename: str, s3_path: str, file_format: str) -> str:
        """Upload content to S3 with AES256 SSE and return the s3:// URL."""
        bucket, key_prefix = self._parse_s3_path(s3_path)

        if key_prefix:
            s3_key = f"{key_prefix}/{filename}" if not key_prefix.endswith('/') else f"{key_prefix}{filename}"
        else:
            s3_key = filename

        content_type = 'application/json' if file_format == 'json' else 'text/csv'
        loop = asyncio.get_running_loop()
        with ThreadPoolExecutor() as executor:
            await loop.run_in_executor(
                executor,
                lambda: self.s3_client.put_object(
                    Bucket=bucket, Key=s3_key,
                    Body=content.encode('utf-8'),
                    ContentType=content_type,
                    ServerSideEncryption='AES256'
                )
            )
        return f"s3://{bucket}/{s3_key}"

    async def _save_to_local_path(self, content: str, filename: str,
                                   file_path: str, file_format: str,
                                   allow_outside_cwd: bool = False) -> str:
        """Write content to a local or network path.

        resolve() normalizes the path; confinement to the working directory
        is enforced by confine_local_path() unless allow_outside_cwd is set.
        """
        path = confine_local_path(file_path, allow_outside_cwd=allow_outside_cwd)
        is_network = self._is_network_path(file_path)

        # Treat paths without a file extension as directories
        if path.is_dir() or file_path.endswith('/') or file_path.endswith('\\') or not path.suffix:
            final_path = path / filename
        else:
            final_path = path

        if is_network:
            await self._create_directory_with_timeout(final_path.parent)
            loop = asyncio.get_running_loop()
            with ThreadPoolExecutor() as executor:
                await asyncio.wait_for(
                    loop.run_in_executor(executor, lambda: final_path.write_text(content)),
                    timeout=30
                )
        else:
            final_path.parent.mkdir(parents=True, exist_ok=True)
            final_path.write_text(content)

        return str(final_path)

    @staticmethod
    def _parse_s3_path(s3_path: str) -> tuple:
        """Split 's3://bucket/prefix' into ('bucket', 'prefix')."""
        parts = s3_path[5:].split('/', 1)
        bucket = parts[0]
        key_prefix = parts[1] if len(parts) > 1 else ''
        return bucket, key_prefix
