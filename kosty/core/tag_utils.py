"""Tag utilities for resource exclusion filtering.

Plugins call should_exclude_resource_by_tags() to check whether a resource
should be skipped based on the tag exclusion rules in kosty.yaml. The
get_resource_tags() helper normalises the various tag formats returned
by different AWS APIs into a consistent list.
"""

from typing import List, Dict, Any, Optional


def should_exclude_resource_by_tags(resource: Dict[str, Any], config_manager) -> bool:
    """Return True if the resource's tags match any exclusion rule in the config.

    Delegates to ConfigManager.should_exclude_by_tags() after extracting
    the tag list from the resource dict.
    """
    if not config_manager:
        return False
    
    tags = resource.get('Tags') or resource.get('tags') or []
    
    if not tags:
        return False
    
    return config_manager.should_exclude_by_tags(tags)


def get_resource_tags(resource: Dict[str, Any], service_type: str = None) -> List[Dict[str, str]]:
    """Extract tags from a resource dict, handling the three formats AWS uses.

    EC2/RDS return 'Tags', IAM returns 'TagList', and some internal
    representations use lowercase 'tags'. service_type is accepted for
    backward compatibility but has no effect.
    """
    return resource.get('Tags') or resource.get('tags') or resource.get('TagList') or []
