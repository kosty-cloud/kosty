import os
import boto3
import json
import platform
from pathlib import Path, PurePath
from typing import Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor
import asyncio

class StorageManager:
    def __init__(self):
        self.s3_client = None
        
    async def validate_save_location(self, save_to: str) -> bool:
        """Validate that we can write to the specified location"""
        if not save_to:
            return True
            
        if save_to.startswith('s3://'):
            return await self._validate_s3_access(save_to)
        else:
            return await self._validate_local_path(save_to)
    
    async def _validate_s3_access(self, s3_path: str) -> bool:
        """Validate S3 write access"""
        try:
            # Parse S3 path
            path_parts = s3_path[5:].split('/', 1)  # Remove 's3://'
            bucket = path_parts[0]
            key_prefix = path_parts[1] if len(path_parts) > 1 else ''
            
            # Initialize S3 client
            self.s3_client = boto3.client('s3')
            
            # Test write access with a small test object
            test_key = f"{key_prefix}/kosty_access_test.txt" if key_prefix else "kosty_access_test.txt"
            
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                # Test put object
                await loop.run_in_executor(
                    executor,
                    lambda: self.s3_client.put_object(
                        Bucket=bucket,
                        Key=test_key,
                        Body=b'test',
                        ServerSideEncryption='AES256'
                    )
                )
                
                # Clean up test object
                await loop.run_in_executor(
                    executor,
                    lambda: self.s3_client.delete_object(Bucket=bucket, Key=test_key)
                )
            
            return True
            
        except Exception as e:
            error_msg = str(e)
            print(f"\n❌ S3 access validation failed:")
            
            if "NoSuchBucket" in error_msg:
                print(f"   • Bucket '{bucket}' does not exist")
            elif "AccessDenied" in error_msg:
                print(f"   • Access denied to bucket '{bucket}'")
                print("   • Ensure you have s3:PutObject permissions")
            elif "InvalidBucketName" in error_msg:
                print(f"   • Invalid bucket name '{bucket}'")
            else:
                print(f"   • {error_msg}")
            
            print(f"\n💡 S3 path format: s3://bucket-name/optional/path/")
            return False
    
    async def _validate_local_path(self, file_path: str) -> bool:
        """Validate local file system write access including network shares"""
        try:
            # Detect network path
            is_network_path = self._is_network_path(file_path)
            
            if is_network_path:
                print(f"🌐 Detected network path: {file_path}")
                print("   • Testing network connectivity...")
            
            # Convert to Path object
            path = Path(file_path)
            
            # Check if it's a directory or file path
            if file_path.endswith('/') or file_path.endswith('\\'):
                # Directory path
                directory = path
                test_file = directory / "kosty_access_test.txt"
            else:
                # File path
                directory = path.parent
                test_file = path.with_suffix('.test')
            
            # Create directory if it doesn't exist (with timeout for network paths)
            if is_network_path:
                await self._create_directory_with_timeout(directory)
            else:
                directory.mkdir(parents=True, exist_ok=True)
            
            # Test write access (with timeout for network paths)
            if is_network_path:
                await self._write_test_file_with_timeout(test_file)
            else:
                test_file.write_text('test')
                test_file.unlink()  # Clean up
            
            if is_network_path:
                print("   ✅ Network path accessible")
            
            return True
            
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
            print(f"   • {str(e)}")
            if self._is_network_path(file_path):
                print("   • Ensure network share is mounted and accessible")
            return False
    
    def _is_network_path(self, file_path: str) -> bool:
        """Detect if path is a network share"""
        # Windows UNC paths (both \\ and // formats)
        if file_path.startswith('\\\\') or file_path.startswith('//'):
            return True
        
        # Common network mount points
        network_prefixes = ['/mnt/', '/media/', '/net/', '/Volumes/']
        return any(file_path.startswith(prefix) for prefix in network_prefixes)
    
    async def _create_directory_with_timeout(self, directory: Path, timeout: int = 10):
        """Create directory with timeout for network paths"""
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as executor:
            await asyncio.wait_for(
                loop.run_in_executor(executor, lambda: directory.mkdir(parents=True, exist_ok=True)),
                timeout=timeout
            )
    
    async def _write_test_file_with_timeout(self, test_file: Path, timeout: int = 10):
        """Write and delete test file with timeout for network paths"""
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as executor:
            # Write test file
            await asyncio.wait_for(
                loop.run_in_executor(executor, lambda: test_file.write_text('test')),
                timeout=timeout
            )
            # Clean up
            await asyncio.wait_for(
                loop.run_in_executor(executor, lambda: test_file.unlink()),
                timeout=timeout
            )
    
    async def save_file(self, content: str, filename: str, save_to: str, file_format: str) -> str:
        """Save file to specified location"""
        if not save_to:
            # Save locally with generated filename
            with open(filename, 'w') as f:
                f.write(content)
            return filename
        
        if save_to.startswith('s3://'):
            return await self._save_to_s3(content, filename, save_to, file_format)
        else:
            return await self._save_to_local_path(content, filename, save_to, file_format)
    
    async def _save_to_s3(self, content: str, filename: str, s3_path: str, file_format: str) -> str:
        """Save file to S3"""
        # Parse S3 path
        path_parts = s3_path[5:].split('/', 1)  # Remove 's3://'
        bucket = path_parts[0]
        key_prefix = path_parts[1] if len(path_parts) > 1 else ''
        
        # Generate S3 key
        if key_prefix:
            if key_prefix.endswith('/'):
                s3_key = f"{key_prefix}{filename}"
            else:
                s3_key = f"{key_prefix}/{filename}"
        else:
            s3_key = filename
        
        # Upload to S3
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as executor:
            await loop.run_in_executor(
                executor,
                lambda: self.s3_client.put_object(
                    Bucket=bucket,
                    Key=s3_key,
                    Body=content.encode('utf-8'),
                    ContentType='application/json' if file_format == 'json' else 'text/csv',
                    ServerSideEncryption='AES256'
                )
            )
        
        s3_url = f"s3://{bucket}/{s3_key}"
        return s3_url
    
    async def _save_to_local_path(self, content: str, filename: str, file_path: str, file_format: str) -> str:
        """Save file to local path including network shares"""
        path = Path(file_path)
        is_network_path = self._is_network_path(file_path)
        
        # Check if path is a directory or file
        if path.is_dir() or file_path.endswith('/') or file_path.endswith('\\') or not path.suffix:
            # Directory path - use generated filename
            final_path = path / filename
        else:
            # Specific file path
            final_path = path
        
        # Ensure directory exists (with timeout for network paths)
        if is_network_path:
            await self._create_directory_with_timeout(final_path.parent)
        else:
            final_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write file (with timeout for network paths)
        if is_network_path:
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as executor:
                await asyncio.wait_for(
                    loop.run_in_executor(executor, lambda: final_path.write_text(content)),
                    timeout=30  # Longer timeout for file write
                )
        else:
            final_path.write_text(content)
        
        return str(final_path)