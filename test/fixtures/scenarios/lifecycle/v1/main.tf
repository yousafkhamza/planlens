terraform {
  required_providers {
    random = { source = "hashicorp/random", version = "~> 3.6" }
    local  = { source = "hashicorp/local", version = "~> 2.5" }
  }
}

variable "names" {
  type    = list(string)
  default = ["alpha", "bravo", "charlie"]
}

# in-place update
resource "terraform_data" "app" {
  input = "v1"
}

# forced replacement via triggers_replace
resource "terraform_data" "replace_me" {
  triggers_replace = ["a"]
}

# generated secret: replacement rotates the value (critical type)
resource "random_password" "db" {
  length  = 16
  special = false
}

# will be renamed without a moved block -> destroy + create
resource "random_pet" "old_name" {
  length    = 2
  separator = "-"
}

# will be renamed WITH a moved block -> no recreate
resource "terraform_data" "moved_old" {
  input = "keep"
}

# count index shift: removing "bravo" shifts "charlie"
resource "local_file" "per_name" {
  count    = length(var.names)
  filename = "${path.module}/out/${count.index}.txt"
  content  = var.names[count.index]
}

# will be removed with `removed { destroy = false }`
resource "terraform_data" "forget_me" {
  input = "x"
}

# will be deleted from config entirely
resource "random_string" "deleted" {
  length = 8
}

# token used by an output later
resource "random_string" "token" {
  length  = 24
  special = false
}

# drift target: file is edited on disk between apply and plan
resource "local_file" "drift" {
  filename = "${path.module}/out/drift.txt"
  content  = "managed by terraform"
}
