# Volatility licensing review

Status: unresolved as of 2026-10-18. The existing MIT grant for original project
material is retained; it is not a determination that the integrated software can
be distributed solely under MIT or that upstream conditions do not apply.

## Why review is needed

The Volatility Software License 1.0 explicitly includes software designed to execute
Volatility and parse its results in its definition of Additions. Covered additions
made available to others must be published under the VSL. The core executes
Volatility and parses its JSON output. Workbench uses that core and its macOS app
bundles the analyzer. Separate processes, environments or repositories do not by
themselves establish an exception. Public source availability alone does not settle
the requirement to offer covered material under the applicable license.

Primary terms: https://volatilityfoundation.org/license/ and the license in the exact
Volatility release being distributed (current macOS packaging selects 2.28.2):
https://github.com/volatilityfoundation/volatility3/blob/v2.28.2/LICENSE.txt

## Resolution before claiming an MIT-only integrated distribution

1. Ask the Volatility Foundation or qualified licensing counsel to confirm the scope
   of covered additions across volatility-mcp, its XP addon and volatility-workbench.
2. Determine whether covered portions must be offered under VSL, and whether any
   independently separable original components can retain MIT alone. If needed,
   obtain written alternative licensing permission from the relevant rightsholders.
3. Check contributor and third-party rights before adopting terms for their material.
   Preserve existing copyright notices and grants; a new file does not erase prior
   licenses or authorize relicensing somebody else's code.
4. Record the decision and exact covered paths, then align LICENSE, package metadata,
   README, notices and release artifacts. Ship required license texts and source.

## Optional plugins and historical references

The community inventory identifies sources without an explicit reuse license and
GPL-derived portions. Optional download does not itself establish permission to
reuse, modify or redistribute them. Keep unresolved sources out of distributed
bundles; obtain permission or replace them with clearly licensed alternatives.
For GPL-derived sources, establish the exact license and corresponding-source and
notice obligations before distribution. Review the XP compatibility implementation's
use of historical Volatility 2 references; source links alone do not establish that
all implementation material can be licensed under MIT.

## Release evidence

Inventory the actual wheel/app/container contents and exact versions. Preserve
dependency license/NOTICE files and verify any required source distribution. Existing
exclusions and notice-copying code help, but are not a complete legal clearance.
No upstream permission or legal opinion has been obtained by this documentation.
