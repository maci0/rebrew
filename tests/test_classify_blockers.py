def test_classify_blockers() -> None:
    from rebrew.match import classify_blockers

    summary = {
        "instructions": [
            {
                "match": "RR",
                "target": {"disasm": "mov eax, ebx"},
                "candidate": {"disasm": "mov edx, ecx"},
            },
            {
                "match": "**",
                "target": {"disasm": "jmp 0x1000"},
                "candidate": {"disasm": "jge 0x1000"},
            },
            {
                "match": "**",
                "target": {"disasm": "xor eax, eax"},
                "candidate": {"disasm": "mov eax, 0"},
            },
            {
                "match": "**",
                "target": {"disasm": "push eax"},
                "candidate": {"disasm": "sub esp, 4"},
            },
        ]
    }
    blockers = classify_blockers(summary)
    assert "register allocation" in blockers
    assert "loop rotation / branch layout" in blockers
    assert "zero-extend pattern (xor vs mov)" in blockers
    assert "stack frame choice (push vs sub esp)" in blockers

    # Test edge cases
    summary_empty = {
        "instructions": [
            {
                "match": "**",
                "target": {"disasm": "   "},
                "candidate": {"disasm": ""},
            },
        ]
    }
    assert classify_blockers(summary_empty) == []
