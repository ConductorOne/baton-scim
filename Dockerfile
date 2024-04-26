FROM gcr.io/distroless/static-debian11:nonroot
ENTRYPOINT ["/baton-scim"]
COPY baton-scim /