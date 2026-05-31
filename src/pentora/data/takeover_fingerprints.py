"""Subdomain takeover service fingerprints."""
from __future__ import annotations

TAKEOVER_FINGERPRINTS: list[dict[str, str]] = [
    {
        "service": "GitHub Pages",
        "cname_contains": "github.io",
        "body_contains": "There isn't a GitHub Pages site here",
    },
    {
        "service": "AWS S3",
        "cname_contains": ".s3.amazonaws.com",
        "body_contains": "NoSuchBucket",
    },
    {
        "service": "Heroku",
        "cname_contains": ".herokudns.com",
        "body_contains": "No such app",
    },
    {
        "service": "Shopify",
        "cname_contains": ".myshopify.com",
        "body_contains": "Sorry, this shop is currently unavailable",
    },
    {
        "service": "Fastly",
        "cname_contains": "fastly.net",
        "body_contains": "Fastly error",
    },
    {
        "service": "Surge",
        "cname_contains": ".surge.sh",
        "body_contains": "project not found",
    },
    {
        "service": "Ghost",
        "cname_contains": ".ghost.io",
        "body_contains": "The thing you were looking for is no longer here",
    },
    {
        "service": "Webflow",
        "cname_contains": ".webflow.io",
        "body_contains": "The page you are looking for doesn't exist",
    },
    {
        "service": "Netlify",
        "cname_contains": ".netlify.com",
        "body_contains": "Not Found - Request ID",
    },
    {
        "service": "Tumblr",
        "cname_contains": ".tumblr.com",
        "body_contains": "There's nothing here",
    },
    {
        "service": "Pantheon",
        "cname_contains": ".pantheonsite.io",
        "body_contains": "The gods are wise",
    },
    {
        "service": "Cargo",
        "cname_contains": ".cargo.site",
        "body_contains": "If you're moving your domain",
    },
    {
        "service": "Azure",
        "cname_contains": ".azurewebsites.net",
        "body_contains": "404 Web Site not found",
    },
    {
        "service": "Cloudfront",
        "cname_contains": ".cloudfront.net",
        "body_contains": "The request could not be satisfied",
    },
    {
        "service": "DigitalOcean",
        "cname_contains": ".github.io",
        "body_contains": "404",
    },
]
