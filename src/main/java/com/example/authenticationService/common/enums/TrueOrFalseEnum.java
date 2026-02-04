package com.example.authenticationService.common.enums;

import static com.example.authenticationService.common.constants.StringsGlobal.Error.INV_INPUT;
import static com.example.authenticationService.common.constants.StringsGlobal.Error.INV_STRING;

public enum TrueOrFalseEnum {
    TRUE(true, 1),
    FALSE(false, 0);

    private final boolean bool;
    private final int num;

    TrueOrFalseEnum(boolean bool, int num) {
        this.bool = bool;
        this.num = num;
    }

    public boolean toBoolean() { return bool; }
    public int toInt() { return num; }

    public static TrueOrFalseEnum from(Object v) {
        if (v == null) return null;
        if (v instanceof TrueOrFalseEnum e) return e;
        if (v instanceof Boolean b) return b ? TRUE : FALSE;
        if (v instanceof Number n) return n.intValue() == 1 ? TRUE : FALSE;

        String s = v.toString().trim().toLowerCase();
        return switch (s) {
            case "true", "t", "1", "yes", "y" -> TRUE;
            case "false","f", "0", "no",  "n" -> FALSE;
            default -> throw new IllegalArgumentException(INV_INPUT + ": " + v);
        };
    }
}
