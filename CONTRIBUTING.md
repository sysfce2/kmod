# Contributing to kmod

Thanks for taking the time to contribute to kmod!

If you want to submit changes, you can send GitHub [pull requests] as well as
patches sent to the [mailing list]. In addition you can open issues and feature
requests on our [GitHub tracker].

## Commit style and history

The kmod project uses a [linear, "recipe" style] history. This means that
commits should be small, digestible, stand-alone, and functional.

Commit messages are in imperative mood and merges are to be avoided.

When in doubt, or need a refresher, checking through the output of `git log` is
highly recommended.

## Using commit trailers

Commit messages, apart from stating why a particular change is made, can include
a range of trailers.

### Signed-off-by

By using a `Signed-off-by:` trailer you agree that you comply with the
[Developer Certificate of Origin](DCO.txt).

### Issues, feature requests

Whenever a patch resolves a particular issue, be that one on our [GitHub
tracker] or elsewhere, use the `Closes:` trailer followed by the full URL.

    Closes: https://github.com/kmod-project/kmod/issues/65

### Discussions, references

If your commit covers a topic raised in an issue, but does not resolve the issue
itself; or otherwise refers to a more complicated topic, you can use
`Reference:`.

### Link(s)

The use of `Link:` trailer is reserved and should be used only to point to the
patch origin. Be that the GitHub pull request, or the mailing list archive.

You can add it yourself, although usually the maintainer will include it when
merging the patch.

### Bugfixes, regressions

Nobody is perfect and regressions happen from time to time. Whenever a commit
addresses a regression caused by another commit, use `Fixes:` as below:

    Fixes: 38943b2 ("shared: use size_t for strbuf")

## Coding style

The project uses style practically identical to the kernel style. You can see
the in-tree [CODING-STYLE file](CODING-STYLE) for quick references.

We also have a [.clang-format file](.clang-format) to ease and enforce the
style. Make sure you run `git-clang-format` against your changes, before
submitting PRs/patches.

## API documentation

The official libkmod documentation is generated by [gtk-doc] and a simple test
is wired to `meson test` to catch accidental mistakes or omissions.

If you're unfamiliar with `gtk-doc` here is a [quick primer].

## Tools manual pages

Our manual pages are written in [scdoc] a simple [markdown-like syntax]. Please
make sure to update them as you add new options to the kmod tools.

## Tools shell completion

The project aims to provide `bash`, `zsh` and `fish` shell completions for all
the kmod tools. Currently support is borderline non-existent, so your help is
greatly appreciated.

[pull requests]: https://github.com/kmod-project/kmod/pull/
[mailing list]: mailto:linux-modules@vger.kernel.org
[GitHub tracker]: https://github.com/kmod-project/kmod/issues/
[linear, "recipe" style]: https://www.bitsnbites.eu/git-history-work-log-vs-recipe/
[gtk-doc]: https://gitlab.gnome.org/GNOME/gtk-doc
[quick primer]: https://gi.readthedocs.io/en/latest/annotations/gtkdoc.html
[scdoc]: https://sr.ht/~sircmpwn/scdoc/
[markdown-like syntax]: https://man.archlinux.org/man/scdoc.5.en