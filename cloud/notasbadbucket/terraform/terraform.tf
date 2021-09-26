provider "google" {
  project = var.project_id
  region  = "australia-southeast1"
  zone    = "australia-southeast1-b"
}

resource "google_storage_bucket" "bucket-bucket" {
  name          = var.bucket_name
  location      = "AUSTRALIA-SOUTHEAST1"
  force_destroy = true
  uniform_bucket_level_access = false
  website {
    main_page_suffix = "index.html"
  }
} 

data "google_iam_policy" "viewer" {
  binding {
    role = "roles/storage.objectViewer"
    members = [
      "allAuthenticatedUsers",
    ]
  }
}

resource "google_storage_bucket_iam_policy" "policy" {
  bucket = google_storage_bucket.bucket-bucket.name
  policy_data = data.google_iam_policy.viewer.policy_data
}

resource "google_storage_bucket_object" "object1" {
  name   = "pics/lisa.jpg"
  source = "../src/pics/lisa.jpg"
  bucket = google_storage_bucket.bucket-bucket.name
  depends_on = [google_storage_bucket.bucket-bucket]
}


resource "google_storage_bucket_object" "object_html" {
  name   = "index.html"
  source = "../src/index.html"
  bucket = google_storage_bucket.bucket-bucket.name
  depends_on = [google_storage_bucket.bucket-bucket]
}

resource "google_storage_bucket_object" "object_flag" {
  name   = "pics/flag.txt"
  source = "../src/pics/flag.txt"
  bucket = google_storage_bucket.bucket-bucket.name
  depends_on = [google_storage_bucket.bucket-bucket]
}