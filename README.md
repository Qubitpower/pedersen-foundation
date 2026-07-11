# Pedersen Commitments

Source for [pedersen.foundation](https://pedersen.foundation) — a plain-spoken,
working explanation of Pedersen commitments (Torben Pedersen, CRYPTO '91) and
the surrounding zero-knowledge context, aimed at engineers rather than
cryptographers.

Every historical claim is sourced (see `/history` and `/further-reading`), and
every interactive demo computes real values client-side — nothing is mocked. See
`/about` for what this site is and how to contribute.

## Stack

- [Astro](https://astro.build) (static output, island architecture)
- Content in MDX (`src/pages/*.mdx`)
- [KaTeX](https://katex.org) for math, via `remark-math`/`rehype-katex`
- [Shiki](https://shiki.style) for code highlighting (Astro's default)
- [`@noble/curves`](https://github.com/paulmillr/noble-curves) for the
  elliptic-curve demos; native `BigInt` for the classic (mod p) demos, no
  dependency — see `src/lib/`

## Development

```sh
npm install
npm run dev      # http://localhost:4321
npm run build    # static output to ./dist
npm run astro check
```

## Contributing

Corrections and additions are welcome — open an issue or a pull request. See
`/about` on the live site for more.

## License

Code is [MIT](LICENSE). Written content is [CC-BY 4.0](LICENSE-CONTENT.md).
