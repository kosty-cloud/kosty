"""Tag utilities for resource exclusion filtering.

Plugins call should_exclude_resource_by_tags() to check whether a resource
should be skipped based on the tag exclusion rules in kosty.yaml. The
get_resource_tags() helper normalises the various tag formats returned
by different AWS APIs into a consistent list.
"""

from typing import List, Dict, Any


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


def excluded_by_tags(resource: Dict[str, Any], kwargs: Dict[str, Any]) -> bool:
    """Return True if the resource's tags match an exclusion rule from kwargs.

    Normalises the resource's tags via get_resource_tags() first so the gate
    also covers APIs that return tags under 'TagList' (RDS), then defers to
    should_exclude_resource_by_tags() as the single matching rule.
    """
    config_manager = kwargs.get('config_manager')
    if not config_manager:
        return False
    return should_exclude_resource_by_tags(
        {'Tags': get_resource_tags(resource)}, config_manager
    )


def get_resource_tags(resource: Dict[str, Any], service_type: str = None) -> List[Dict[str, str]]:
    """Extract tags from a resource dict, handling the three formats AWS uses.

    EC2/RDS return 'Tags', IAM returns 'TagList', and some internal
    representations use lowercase 'tags'. service_type is accepted for
    backward compatibility but has no effect.
    """
    return resource.get('Tags') or resource.get('tags') or resource.get('TagList') or []
