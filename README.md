# abraxas.pages.dev

Nothing interesting, just the source code for my personal blog.
Built with [Hugo](https://gohugo.io/) and the [Congo](https://jpanther.github.io/congo/) theme

The blog is hosted with [Cloudflare Pages](https://pages.cloudflare.com/)

**Tech stack** at the time of writing

- hugo version 0.113.0+extended
- go version go1.20.4

To run the blog locally, use the following command. The -D flag will also display draft posts and `--disableFastRender` to disable Fast render mode.

```sh
hugo server -D
```

Create new blog post using the blog archetype

```sh
hugo new blog/<blog-title>/index.md
```

Create new post based on the htb archtype

```sh
hugo new --kind htb blog/htb-<box-name>
```

## July 2025 Update

- Bump Hugo version to 0.148.0
- Set build config framework as hugo
- Build system version set to 3 for production and preview

## ToDo

- [ ] Migrate from [pages to workers](https://developers.cloudflare.com/workers/static-assets/migration-guides/migrate-from-pages/)
