# Bundled terraform ruleset only, so tflint needs no plugin download.
# The AWS ruleset is not enabled: its useful rules need provider credentials,
# and the lint job runs without them.

plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

# Files are split by concern instead of collapsed into main.tf, which reads
# better in a pull request.
rule "terraform_standard_module_structure" {
  enabled = false
}
