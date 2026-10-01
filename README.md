<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="apps/web/public/logo-wordmark-invert.png">
  <img src="apps/web/public/logo-wordmark.png" alt="Inkloom" width="280">
</picture>

**Specialised AI models for logo design.**

[inkloom.art](https://inkloom.art)

</div>

---

## What we are building

A logo is not a picture. It is a constructed object with rules: a mark that
holds at sixteen pixels and on the side of a building, letterforms spaced by
eye rather than by metric, clear space derived from the mark's own geometry,
and lockups that still read when one of them is all you have room for.

General image models do not work this way. They produce something
logo-shaped — a plausible arrangement of marks with no construction behind it,
no reasoning about the business, and nothing you can hand to a printer or a
sign maker.

Inkloom is building models that construct a mark the way a studio does, as a
sequence of decisions that can each be explained:

| Stage                   | What it produces                                                                                                                                                                       |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Brand analysis**      | Turns a description of a business — sector, audience, tone, competitors — into concrete constraints: stroke weight, width, geometry, counter shape, which symbol families fit          |
| **Typography**          | Selects and fits letterforms against those constraints, then does the work that makes a wordmark: optical spacing, kerning at display size, a custom ligature where the name needs one |
| **Symbol construction** | Composes geometric primitives under construction rules — shared radii, tangent junctions, consistent terminals — so the result is built rather than sampled                            |
| **Composition**         | Optical alignment rather than mathematical centring, clear-space ratios taken from the mark itself, and the lockup variants a brand actually needs                                     |

The output is meant to be a specification, not a bitmap: a mark you can describe,
defend and reproduce.

---

## Where we are

**Early access is open at [inkloom.art](https://inkloom.art).** Create an
account, redeem a code, and credits are reserved against your account.

**Generation is not live yet.** We would rather say that plainly than imply
otherwise: every page in the product says so, credits are described as reserved
rather than spendable, and the feature flags that would switch generation on
default to off and are not togglable from the console — because enabling a flag
whose feature does not exist exposes a broken surface rather than a feature.

What runs today is the platform the models will ship on. Accounts and
authentication, the credit ledger, the access-code system, the operations
console, and the machinery around them: backups that are restore-tested rather
than merely taken, an alerting pair where each half watches what the other
cannot see, and a deployment path that refuses to migrate a database whose
identity has not been confirmed.

### What comes next

Generation itself, then the things that only make sense once it exists: export
in the formats a designer and a printer each need, brand kits, revision history
on a mark, and paid plans. None of it is claimed as present until it is.

---

## About this repository

This source is published so the engineering can be read and audited — in
particular the security and data-handling claims we make. It is not a
distribution: see [LICENCE](LICENCE).

Found a security issue? [SECURITY.md](SECURITY.md) says where to send it and
what to expect. Please do not open a public issue.

Operational documentation — deployment, incident response, environment and
runbooks — is kept internal. Source comments occasionally point at it by
filename; that is a reference for the people who run the service, not a broken
link. It describes how the service is operated, which is of no use to a reader
and of some use to an attacker.

Built on Cloudflare Workers, Postgres and React Router, with the application and
its API served from one origin — which is what makes the session cookie
first-party and removes cross-origin handling entirely.

The test suite runs against a real database, a real browser and a real mail
server rather than mocks of any of them, because the guarantees that matter here
are transaction guarantees and a mock cannot have one. The test that matters
most fires twenty-five simultaneous redemptions of a single code at a real
database and asserts that exactly one redemption, one ledger entry and one
balance exist afterwards.

---

## Contact

|          |                                                                       |
| -------- | --------------------------------------------------------------------- |
| General  | <support@inkloom.art>                                                 |
| Security | <security@inkloom.art> — please read [SECURITY.md](SECURITY.md) first |

---

<div align="center">

Copyright © Inkloom. All rights reserved.

</div>


## 🌐 Web Resources & Aesthetic Symbols Index
- [SYM 1D46F](https://clean-unicode-text-68.pages.dev/symbol/sym-1d46f/)
- [BRACKETS](https://pastel-chibi-fonts-48.pages.dev/pt/brackets/)
- [SYM 1F63A](https://mecha-gamer-bios-40.pages.dev/symbol/sym-1f63a/)
- [VIRGO ZODIAC MAIDEN](https://cyber-clan-tags-68.pages.dev/symbol/virgo-zodiac-maiden/)
- [SYM 1D438](https://occult-rune-symbols-64.pages.dev/symbol/sym-1d438/)
- [SYM 2620 FE0F](https://anime-sparkle-text-24.pages.dev/symbol/sym-2620-fe0f/)
- [SYM 1F4A9](https://minimal-star-symbols-35.pages.dev/symbol/sym-1f4a9/)
- [SYM 26D3](https://tech-glitch-symbols-36.pages.dev/symbol/sym-26d3/)
- [SYM 1F495](https://mecha-crosshair-tags-20.pages.dev/symbol/sym-1f495/)
- [SYM 2689](https://neon-gamer-symbols-64.pages.dev/symbol/sym-2689/)
- [STAR OPERATOR](https://gothic-bio-fonts-55.pages.dev/symbol/star-operator/)
- [INSTAGRAM BIO](https://matrix-glitch-text-59.pages.dev/es/instagram-bio/)
- [SYM 1F619](https://balletcore-unicode-67.pages.dev/symbol/sym-1f619/)
- [SYM 1F47F](https://classic-typewriter-symbols-19.pages.dev/symbol/sym-1f47f/)
- [SYM 2617](https://grimoire-magic-symbols-81.pages.dev/symbol/sym-2617/)
- [LOVING HEART EYES KAOMOJI](https://balletcore-unicode-67.pages.dev/symbol/loving-heart-eyes-kaomoji/)
- [SYM 1D449](https://matrix-glitch-text-59.pages.dev/symbol/sym-1d449/)
- [SYM 267D](https://neon-gamer-symbols-64.pages.dev/symbol/sym-267d/)
- [SYM 1D409](https://zen-unicode-text-36.pages.dev/symbol/sym-1d409/)
- [GAMING WEAPONS](https://angelic-soft-text-59.pages.dev/vi/gaming-weapons/)
- [SYM 1D497](https://grimoire-magic-symbols-81.pages.dev/symbol/sym-1d497/)
- [ROYAL GOLD CROWN](https://coquette-aesthetic-symbols-78.pages.dev/symbol/royal-gold-crown/)
- [SYM 2733](https://matrix-glitch-text-59.pages.dev/symbol/sym-2733/)
- [NATURE FLOWERS](https://balletcore-unicode-67.pages.dev/pt/nature-flowers/)
- [LEFT WHITE CORNER BRACKET](https://balletcore-unicode-67.pages.dev/symbol/left-white-corner-bracket/)
- [SYM 26DF](https://sleek-border-symbols-37.pages.dev/symbol/sym-26df/)
- [ROBLOX NAMES](https://soft-angel-symbols-61.pages.dev/vi/roblox-names/)
- [BLACK FOUR POINT STAR](https://balletcore-unicode-67.pages.dev/symbol/black-four-point-star/)
- [SYM 1F970](https://neon-matrix-symbols-57.pages.dev/symbol/sym-1f970/)
- [HEAVY RIGHTWARD ARROW](https://classic-typewriter-symbols-19.pages.dev/symbol/heavy-rightward-arrow/)
- [SYM 26E4](https://kawaii-kaomoji-hub-17.pages.dev/symbol/sym-26e4/)
- [SAGITTARIUS ZODIAC ARCHER](https://kawaii-kaomoji-hub-99.pages.dev/symbol/sagittarius-zodiac-archer/)
- [LEO ZODIAC LION](https://mecha-crosshair-tags-20.pages.dev/symbol/leo-zodiac-lion/)
- [SYM 1D41D](https://cyber-clan-tags-15.pages.dev/symbol/sym-1d41d/)
- [TRENDING](https://mecha-crosshair-tags-20.pages.dev/ru/trending/)
- [PISCES ZODIAC FISHES](https://balletcore-unicode-67.pages.dev/symbol/pisces-zodiac-fishes/)
- [SYM 1D4A3](https://mecha-crosshair-tags-20.pages.dev/symbol/sym-1d4a3/)
- [KAOMOJI](https://soft-girl-fancy-text-11.pages.dev/pt/kaomoji/)
- [INSTAGRAM BIO](https://balletcore-unicode-67.pages.dev/ru/instagram-bio/)
- [SYM 1D433](https://coquette-aesthetic-symbols-29.pages.dev/symbol/sym-1d433/)
- [SYM 2731](https://clean-aesthetic-fonts-74.pages.dev/symbol/sym-2731/)
- [STARS](https://minimal-star-symbols-32.pages.dev/stars/)
- [BRACKETS](https://zen-unicode-text-36.pages.dev/pt/brackets/)
- [SYM 1D442](https://kawaii-kaomoji-hub-17.pages.dev/symbol/sym-1d442/)
- [SYM 1D42C](https://kawaii-kaomoji-hub-17.pages.dev/symbol/sym-1d42c/)
- [SYM 2688](https://neon-gamer-symbols-64.pages.dev/symbol/sym-2688/)
- [SYM 1D49B](https://matrix-glitch-text-59.pages.dev/symbol/sym-1d49b/)
- [PINWHEEL STAR](https://sleek-unicode-art-69.pages.dev/symbol/pinwheel-star/)
- [SYM 26EA](https://balletcore-unicode-67.pages.dev/symbol/sym-26ea/)
- [SYM 2656](https://vintage-bow-fonts-72.pages.dev/symbol/sym-2656/)
- [ARROWS LINES](https://minimal-star-symbols-32.pages.dev/es/arrows-lines/)
- [DAGGER BLADE](https://subtle-arrow-fonts-98.pages.dev/symbol/dagger-blade/)
- [SYM 1D470](https://kawaii-kaomoji-hub-99.pages.dev/symbol/sym-1d470/)
- [SYM 1F604](https://vintage-scholar-text-78.pages.dev/symbol/sym-1f604/)
- [SYM 1F649](https://minimal-star-symbols-32.pages.dev/symbol/sym-1f649/)
- [SYM 1D430](https://kawaii-kaomoji-hub-17.pages.dev/symbol/sym-1d430/)
- [SYM 1D467](https://balletcore-unicode-67.pages.dev/symbol/sym-1d467/)
- [TIKTOK CAPTIONS](https://matrix-unicode-symbols-12.pages.dev/ja/tiktok-captions/)
- [SYM 2685](https://neon-gamer-symbols-64.pages.dev/symbol/sym-2685/)
- [SYM 1D45D](https://neon-gamer-symbols-64.pages.dev/symbol/sym-1d45d/)
- [SYM 2682](https://neon-gamer-symbols-64.pages.dev/symbol/sym-2682/)
- [SYM 1D493](https://angelic-soft-fonts-31.pages.dev/symbol/sym-1d493/)
- [SYM 1D473](https://clean-sparkle-text-75.pages.dev/symbol/sym-1d473/)
- [SYM 2721](https://clean-sparkle-text-75.pages.dev/symbol/sym-2721/)
- [SYM 1D432](https://pastel-chibi-kaomoji-14.pages.dev/symbol/sym-1d432/)
- [SYM 1D428](https://soft-angel-symbols-33.pages.dev/symbol/sym-1d428/)
- [WARM HUG EMBRACE KAOMOJI](https://simple-line-kaomoji-30.pages.dev/symbol/warm-hug-embrace-kaomoji/)
- [SYM 1D481](https://neon-gamer-symbols-64.pages.dev/symbol/sym-1d481/)
- [SWIMMING FISH RIGHT](https://sleek-unicode-art-69.pages.dev/symbol/swimming-fish-right/)
- [ROBLOX NAMES](https://minimal-star-symbols-32.pages.dev/ja/roblox-names/)
- [SYM 26C1](https://clean-sparkle-text-75.pages.dev/symbol/sym-26c1/)
- [SYM 26D4](https://balletcore-unicode-67.pages.dev/symbol/sym-26d4/)
- [SYM 1D48D](https://angelic-soft-fonts-31.pages.dev/symbol/sym-1d48d/)
- [INSTAGRAM BIO](https://matrix-unicode-symbols-12.pages.dev/instagram-bio/)
- [BORDERS DIVIDERS](https://glitch-matrix-symbols-22.pages.dev/pt/borders-dividers/)
- [SYM 1F624](https://classic-literature-runes-13.pages.dev/symbol/sym-1f624/)
- [SYM 1F49C](https://pink-ribbon-fonts-28.pages.dev/symbol/sym-1f49c/)
- [SYM 265D](https://balletcore-unicode-67.pages.dev/symbol/sym-265d/)
- [SYM 1D43E](https://pure-dot-symbols-31.pages.dev/symbol/sym-1d43e/)
- [BORDERS DIVIDERS](https://balletcore-unicode-67.pages.dev/pt/borders-dividers/)
- [CIRCLED STAR](https://matrix-unicode-symbols-12.pages.dev/symbol/circled-star/)
- [RIGHT HEAVY BRACKET BOX](https://balletcore-unicode-67.pages.dev/symbol/right-heavy-bracket-box/)
- [SYM 2666](https://pastel-chibi-kaomoji-14.pages.dev/symbol/sym-2666/)
- [SYM 1D4A5](https://minimal-star-symbols-32.pages.dev/symbol/sym-1d4a5/)
- [BRACKETS](https://balletcore-unicode-67.pages.dev/vi/brackets/)
- [SYM 1F63A](https://academic-rune-text-25.pages.dev/symbol/sym-1f63a/)
- [SYM 273E](https://baroque-unicode-decor-43.pages.dev/symbol/sym-273e/)
- [SYM 1F498](https://pastel-chibi-kaomoji-14.pages.dev/symbol/sym-1f498/)
- [SYM 1F64A](https://pink-ribbon-fonts-28.pages.dev/symbol/sym-1f64a/)
- [LEFT MATHEMATICAL WHITE SQUARE BRACKET](https://angelic-soft-text-59.pages.dev/symbol/left-mathematical-white-square-bracket/)
- [SYM 1F92C](https://pastel-chibi-kaomoji-14.pages.dev/symbol/sym-1f92c/)
- [SYM 1F97A](https://kawaii-kaomoji-hub-31.pages.dev/symbol/sym-1f97a/)
- [SYM 1F97A](https://minimal-star-symbols-32.pages.dev/symbol/sym-1f97a/)
- [CHEERING FIGHTING FIST KAOMOJI](https://chibi-heart-symbols-15.pages.dev/symbol/cheering-fighting-fist-kaomoji/)
- [SYM 1D484](https://soft-angel-text-44.pages.dev/symbol/sym-1d484/)
- [SYM 1D461](https://balletcore-unicode-67.pages.dev/symbol/sym-1d461/)
- [SYM 26FB](https://pastel-chibi-fonts-48.pages.dev/symbol/sym-26fb/)
- [SYM 2642](https://pink-ribbon-fonts-28.pages.dev/symbol/sym-2642/)
- [MUSIC WEATHER](https://matrix-unicode-symbols-12.pages.dev/es/music-weather/)
- [SYM 26A8](https://matrix-unicode-symbols-12.pages.dev/symbol/sym-26a8/)
- [HEARTS](https://cute-face-emoticons-66.pages.dev/es/hearts/)
- [SYM 1D43F](https://vampiric-text-craft-82.pages.dev/symbol/sym-1d43f/)
- [RIGHT HEAVY BRACKET BOX](https://coquette-aesthetic-symbols-51.pages.dev/symbol/right-heavy-bracket-box/)
- [SYM 1F63E](https://minimal-star-symbols-35.pages.dev/symbol/sym-1f63e/)
- [RIGHT WING CLAN FLARE](https://anime-sparkle-text-81.pages.dev/symbol/right-wing-clan-flare/)
- [SYM 1D437](https://zen-unicode-hub-94.pages.dev/symbol/sym-1d437/)
- [SYM 1D44B](https://anime-sparkle-text-14.pages.dev/symbol/sym-1d44b/)
- [SYM 1F636 200D 1F32B FE0F](https://sleek-unicode-art-69.pages.dev/symbol/sym-1f636-200d-1f32b-fe0f/)
- [SYM 273B](https://neon-hacker-text-25.pages.dev/symbol/sym-273b/)
- [SYM 1F972](https://synth-crosshair-text-47.pages.dev/symbol/sym-1f972/)
- [SYM 1F974](https://zen-spacing-text-68.pages.dev/symbol/sym-1f974/)
- [ARROWS LINES](https://sleek-bio-symbols-40.pages.dev/pt/arrows-lines/)
- [INSTAGRAM BIO](https://balletcore-unicode-67.pages.dev/ja/instagram-bio/)
- [SYM 1D444](https://kawaii-kaomoji-hub-77.pages.dev/symbol/sym-1d444/)
- [SYM 1F60A](https://mecha-matrix-symbols-75.pages.dev/symbol/sym-1f60a/)
- [SYM 26B7](https://pink-ribbon-fonts-28.pages.dev/symbol/sym-26b7/)
- [SYM 26B2](https://matrix-unicode-symbols-12.pages.dev/symbol/sym-26b2/)
- [SYM 1F60B](https://coquette-aesthetic-symbols-31.pages.dev/symbol/sym-1f60b/)
- [SYM 1D462](https://zen-dot-symbols-91.pages.dev/symbol/sym-1d462/)
- [SYM 1F974](https://soft-angel-text-44.pages.dev/symbol/sym-1f974/)
- [CUPID FEATHERY ARROW](https://cyber-clan-tags-41.pages.dev/symbol/cupid-feathery-arrow/)
- [SYM 1D468](https://kawaii-kaomoji-hub-31.pages.dev/symbol/sym-1d468/)
- [CHEERING FIGHTING FIST KAOMOJI](https://minimal-star-symbols-26.pages.dev/symbol/cheering-fighting-fist-kaomoji/)
- [SYM 26E0](https://kawaii-kaomoji-hub-17.pages.dev/symbol/sym-26e0/)
- [SYM 1D404](https://cyber-clan-tags-75.pages.dev/symbol/sym-1d404/)
- [SYM 2667](https://occult-runic-fonts-23.pages.dev/symbol/sym-2667/)
- [SYM 2626](https://clean-mono-fonts-64.pages.dev/symbol/sym-2626/)
- [LATIN CROSS FAITH](https://coquette-aesthetic-symbols-76.pages.dev/symbol/latin-cross-faith/)
- [SYM 1D474](https://cyber-clan-tags-69.pages.dev/symbol/sym-1d474/)
- [SYM 26B2](https://mecha-matrix-symbols-75.pages.dev/symbol/sym-26b2/)
