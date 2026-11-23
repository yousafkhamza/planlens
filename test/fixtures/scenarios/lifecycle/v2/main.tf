terraform {
  required_providers {
    random = { source = "hashicorp/random", version = "~> 3.6" }
    local  = { source = "hashicorp/local", version = "~> 2.5" }
  }
}

variable "names" {
  type    = list(string)
  default = ["alpha", "charlie"]
}

resource "terraform_data" "app" {
  input = "v2"
}

resource "terraform_data" "replace_me" {
  triggers_replace = ["b"]
}

resource "random_password" "db" {
  length  = 20
  special = false
}

resource "random_pet" "new_name" {
  length    = 2
  separator = "-"
}

resource "terraform_data" "moved_new" {
  input = "keep"
}

moved {
  from = terraform_data.moved_old
  to   = terraform_data.moved_new
}

resource "local_file" "per_name" {
  count    = length(var.names)
  filename = "${path.module}/out/${count.index}.txt"
  content  = var.names[count.index]
}

removed {
  from = terraform_data.forget_me
  lifecycle {
    destroy = false
  }
}

resource "random_string" "token" {
  length  = 24
  special = false
}

resource "local_file" "drift" {
  filename = "${path.module}/out/drift.txt"
  content  = "managed by terraform"
}

resource "random_id" "imported" {
  byte_length = 4
}

import {
  to = random_id.imported
  id = "p-9hUg"
}

output "api_token" {
  value = random_string.token.result
}

output "db_password" {
  value     = random_password.db.result
  sensitive = true
}
