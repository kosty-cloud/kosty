"""Tag utilities for resource filtering"""

from typing import List, Dict, Any, Optional


def should_exclude_resource_by_tags(resource: Dict[str, Any], config_manager) -> bool:
    """Check if resource should be excluded based on tags
    
    Args:
        resource: Resource dict that may contain 'Tags' or 'tags' field
        config_manager: ConfigManager instance
    
    Returns:
        True if resource should be excluded, False otherwise
    """
    if not config_manager:
        return False
    
    tags = resource.get('Tags') or resource.get('tags') or []
    
    if not tags:
        return False
    
    return config_manager.should_exclude_by_tags(tags)


def get_resource_tags(resource: Dict[str, Any], service_type: str = None) -> List[Dict[str, str]]:
    """Extract tags from resource in various formats
    
    Args:
        resource: Resource dict that may contain tags
        service_type: Service type (accepted for backward compatibility, not used)
    
    Returns:
        List of tag dicts with 'Key' and 'Value' fields
    """
    return resource.get('Tags') or resource.get('tags') or resource.get('TagList') or []
