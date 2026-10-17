"""Offline tests for kosty.core.tag_utils tag normalisation and exclusion.

No boto3/STS/network: resources are plain dicts and the config manager is a
small stub, so the matching logic is exercised directly.
"""

from kosty.core.tag_utils import (
    get_resource_tags,
    should_exclude_resource_by_tags,
    excluded_by_tags,
)


class _TagStubConfig:
    """Minimal ConfigManager stand-in exposing should_exclude_by_tags."""

    def __init__(self, rules):
        self._rules = rules

    def should_exclude_by_tags(self, resource_tags):
        for rule in self._rules:
            key = rule.get('key')
            value = rule.get('value')
            for tag in resource_tags:
                tag_key = tag.get('Key') or tag.get('key')
                tag_value = tag.get('Value') or tag.get('value')
                if tag_key == key and (value is None or tag_value == value):
                    return True
        return False


def test_get_resource_tags_reads_tags_format():
    """EC2/RDS 'Tags' list is returned as-is."""
    resource = {'Tags': [{'Key': 'env', 'Value': 'prod'}]}
    assert get_resource_tags(resource) == [{'Key': 'env', 'Value': 'prod'}]


def test_get_resource_tags_reads_lowercase_tags():
    """Internal lowercase 'tags' is honoured when 'Tags' is absent."""
    resource = {'tags': [{'key': 'team', 'value': 'core'}]}
    assert get_resource_tags(resource) == [{'key': 'team', 'value': 'core'}]


def test_get_resource_tags_reads_taglist_format():
    """IAM 'TagList' is honoured when 'Tags'/'tags' are absent."""
    resource = {'TagList': [{'Key': 'owner', 'Value': 'ops'}]}
    assert get_resource_tags(resource) == [{'Key': 'owner', 'Value': 'ops'}]


def test_get_resource_tags_empty_when_no_tags():
    """A resource with no tag field yields an empty list."""
    assert get_resource_tags({'ResourceId': 'r-1'}) == []


def test_get_resource_tags_takes_single_argument():
    """The dead service_type parameter is gone — the signature takes one arg."""
    import inspect

    params = list(inspect.signature(get_resource_tags).parameters)
    assert params == ['resource']


def test_should_exclude_resource_by_tags_matches_rule():
    """A resource tagged to match an exclusion rule is excluded."""
    cfg = _TagStubConfig([{'key': 'env', 'value': 'prod'}])
    resource = {'Tags': [{'Key': 'env', 'Value': 'prod'}]}
    assert should_exclude_resource_by_tags(resource, cfg) is True


def test_should_exclude_resource_by_tags_no_match():
    """A non-matching tag set is not excluded."""
    cfg = _TagStubConfig([{'key': 'env', 'value': 'prod'}])
    resource = {'Tags': [{'Key': 'env', 'Value': 'dev'}]}
    assert should_exclude_resource_by_tags(resource, cfg) is False


def test_should_exclude_resource_by_tags_no_config():
    """Without a config manager, nothing is excluded."""
    resource = {'Tags': [{'Key': 'env', 'Value': 'prod'}]}
    assert should_exclude_resource_by_tags(resource, None) is False


def test_excluded_by_tags_normalises_taglist():
    """excluded_by_tags normalises a TagList resource before matching."""
    cfg = _TagStubConfig([{'key': 'env', 'value': 'prod'}])
    resource = {'TagList': [{'Key': 'env', 'Value': 'prod'}]}
    assert excluded_by_tags(resource, {'config_manager': cfg}) is True


def test_excluded_by_tags_no_config():
    """excluded_by_tags is a no-op without a config manager in kwargs."""
    resource = {'TagList': [{'Key': 'env', 'Value': 'prod'}]}
    assert excluded_by_tags(resource, {}) is False
