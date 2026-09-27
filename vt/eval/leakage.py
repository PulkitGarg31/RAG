def question_leaks_identifiers(question: str, package: str, ids: list[str]) -> bool:
    lowered = question.lower()
    if package.lower() in lowered:
        return True
    return any(identifier.lower() in lowered for identifier in ids)
