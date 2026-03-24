from devsec_lint.rules.github_actions.latest_tag import LatestTagRule
from devsec_lint.rules.github_actions.missing_permissions import MissingPermissionsRule
from devsec_lint.rules.github_actions.unpinned_action import UnpinnedActionRule
from devsec_lint.rules.github_actions.unpinned_image import UnpinnedImageRule

RULES = [
    UnpinnedActionRule(),
    UnpinnedImageRule(),
    MissingPermissionsRule(),
    LatestTagRule(),
]