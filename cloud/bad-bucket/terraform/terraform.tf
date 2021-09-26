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
      "allUsers",
    ]
  }
}

resource "google_storage_bucket_iam_policy" "policy" {
  bucket = google_storage_bucket.bucket-bucket.name
  policy_data = data.google_iam_policy.viewer.policy_data
}

resource "google_storage_bucket_object" "object1" {
  name   = "buckets/bucket1.jpg"
  source = "../src/buckets/bucket1.jpg"
  bucket = google_storage_bucket.bucket-bucket.name
  depends_on = [google_storage_bucket.bucket-bucket]
}

resource "google_storage_bucket_object" "object2" {
  name   = "buckets/bucket2.jpg"
  source = "../src/buckets/bucket2.jpg"
  bucket = google_storage_bucket.bucket-bucket.name
  depends_on = [google_storage_bucket.bucket-bucket]
}

resource "google_storage_bucket_object" "object3" {
  name   = "buckets/bucket3.png"
  source = "../src/buckets/bucket3.png"
  bucket = google_storage_bucket.bucket-bucket.name
  depends_on = [google_storage_bucket.bucket-bucket]
}

resource "google_storage_bucket_object" "object4" {
  name   = "buckets/bucket4.png"
  source = "../src/buckets/bucket4.png"
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
  name   = "buckets/.notaflag"
  source = "../src/buckets/.notaflag"
  bucket = google_storage_bucket.bucket-bucket.name
  depends_on = [google_storage_bucket.bucket-bucket]
}

