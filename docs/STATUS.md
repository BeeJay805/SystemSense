# Project status

## NOW

- The kernel now captures crash-safe bookmarked Event Log evidence, maintains
  timestamped inventory, and collects bounded live core Windows and resource state.

## NEXT

- Add application/process/service evidence, device and driver evidence, and networking state.

## BLOCKED

- None.

## LESSON

- Content identity deduplicates bytes; access authority remains a separate case-artifact relation.
- Optional evidence sources are coverage states; they are never startup dependencies.
- Live Windows API tests are required because fixture tests cannot expose pywin32 handle differences.
