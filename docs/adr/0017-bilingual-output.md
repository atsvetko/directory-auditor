# ADR-0017: All user-facing check text is bilingual (EN/RU) in the catalogue itself

**Status:** accepted (2026-10-07) · approach §11 (languages), market decision (global + RU)

## Context
The market is both global and Russian; RU-stack coverage (Samba, FreeIPA/ALD Pro) is the
differentiator. Translations kept apart from the checks drift; Russian security text must use
ГОСТ / БДУ ФСТЭК terminology, not ad-hoc translation.

## Decision
- Titles and remediation carry `en` and `ru` in the same catalogue entry; the engine is
  language-neutral and the report picks the language.
- Russian text follows the project's controlled vocabulary («учётная запись», not
  «идентичность»).

## Alternatives
- **English only, community translations later** — rejected: fails the RU market at launch.
- **Separate i18n files** — rejected: reviewers would have to read two files per check.

## Consequences
- Each new check costs translation work; the loader rejects entries missing either language.
