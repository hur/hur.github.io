+++
title = "Scalable CTF infrastructure on GCP & Digital Ocean"
date = 2022-08-31
summary = true

[taxonomies]
categories = ["security"]
+++

This post is about the infrastructure behind pwnEd 3, the third installment of the annual CTF competition hosted by SIGINT. This time, 45 teams or approximately 155 users signed up. We used Google Cloud Platform to host CTFd, and DigitalOcean to host our challenges on a Kubernetes cluster. In this post, I'm going to share our architecture and a few tricky bits we faced while setting the CTF up.
<!-- more -->

## CTFd

We wanted our CTFd deployment to be able to scale for larger CTFs we might host. Furthermore, by using Infrastructure as Code tools like Terraform and documenting the deployment process, we can ensure that future members of the society are able to also host CTFs with ease, without having to solve the same problems again.

We deploy CTFd on App Engine, backed by Cloud SQL and Memorystore Redis. Challenge files are served from a Cloud Storage Bucket.

The full Terraform source for our CTFd deployment is available at [hur/ctfd-gcp](https://github.com/hur/ctfd-gcp)


![CTFd Architecture diagram](https://raw.githubusercontent.com/hur/ctfd-gcp/master/docs/architecture_overview.svg)

The applications are deployed in a VPC, and only App Engine has a public IP address, and sits behind the App Engine load balancer, allowing us to add instances of CTFd easily. We used manual scaling in order for costs to be more predictable, but App Engine supports autoscaling and it is easily enabled if the number of instances is more volatile.

Cloud SQL and Redis are also easily configured with High Availability without having to worry about implementation details, making scaling up easier.

One thing to note when configuring CTFd in App Engine is that the `REVERSE_PROXY` variable needs to be set correctly. This is necessary for CTFd to correctly handle `X-Forwarded-` headers and enables it to correctly determine visitor IP addresses in the authentication log. 

In our case, we are behind the App Engine load balancer and also the Cloudflare CDN, so we set 
```tf
resource "google_app_engine_flexible_app_version" "ctfd" {
    ...
    env_variables = {
        REVERSE_PROXY = "2,1,0,0,0"
    }
```

Furthermore, in order to get CTFd working with GCP's storage buckets, 
we need to configure [interoperability](https://cloud.google.com/storage/docs/interoperability) using the V4 signing process and HMAC keys. 

In terraform, we achieve this by adding an interop service account
```tf
# Enable access key and secret to use with CTFd
resource "google_service_account" "interop_account" {
    account_id = "interop"
    project = google_project.ctf.project_id
}
```
adding an HMAC key to the interop service account
```tf
resource "google_storage_hmac_key" "interop_key" {
    service_account_email = google_service_account.interop_account.email
}
```
and adding the service account as an IAM member to the bucket with the role `storage.objectAdmin`
```tf
resource "google_storage_bucket_iam_member" "interop_iam" {
    bucket = google_storage_bucket.challenge_files.name
    role = "roles/storage.objectAdmin"
    member = "serviceAccount:${google_service_account.interop_account.email}"
}
```
Then, we can set the environment variables for CTFd like it was an S3 bucket.
```tf
resource "google_app_engine_flexible_app_version" "ctfd" {
    ...
    env_variables = {
        ...
        AWS_ACCESS_KEY_ID = google_storage_hmac_key.interop_key.access_id
        AWS_SECRET_ACCESS_KEY = google_storage_hmac_key.interop_key.secret
        AWS_S3_BUCKET = google_storage_bucket.challenge_files.name
    }
```
Now, we can serve challenge files via CTFd from a Cloud Storage Bucket without having to make the bucket public!

Lastly, one small thing with CTFd v3.4.1 is that it did not support configuring the port it runs on. App Engine Flex requires the applications to listen on port 8080, but CTFd listens on port 8000. We had to apply the following patch to circumvent this problem (thanks to the folks at DownUnderCTF for [this](https://github.com/DownUnderCTF/ctfd-appengine/blob/master/patch.txt):
```
diff -ruN original/docker-entrypoint.sh changes/docker-entrypoint.sh
--- original/docker-entrypoint.sh
+++ changes/docker-entrypoint.sh
@@ -5,6 +5,8 @@
 WORKER_CLASS=${WORKER_CLASS:-gevent}
 ACCESS_LOG=${ACCESS_LOG:--}
 ERROR_LOG=${ERROR_LOG:--}
+WORKER_TIMEOUT=${WORKER_TIMEOUT:-60}
+WORKER_PORT=${WORKER_PORT:-8080}
 WORKER_TEMP_DIR=${WORKER_TEMP_DIR:-/dev/shm}
 SECRET_KEY=${SECRET_KEY:-}
 DATABASE_URL=${DATABASE_URL:-}
@@ -42,8 +44,9 @@
 # Start CTFd
 echo "Starting CTFd"
 exec gunicorn 'CTFd:create_app()' \
-    --bind '0.0.0.0:8000' \
+    --bind "0.0.0.0:$WORKER_PORT" \
     --workers $WORKERS \
+    --timeout $WORKER_TIMEOUT \
     --worker-tmp-dir "$WORKER_TEMP_DIR" \
     --worker-class "$WORKER_CLASS" \
     --access-logfile "$ACCESS_LOG" \
```

For details on how this integrated to our Terraform deployment and the CTFd Dockerfile, see the repository linked above. 

Since this post became so long, Kubernetes and the challenge cluster will be described in another post.
