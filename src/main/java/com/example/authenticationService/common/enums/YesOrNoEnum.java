package com.example.authenticationService.common.enums;

import static com.example.authenticationService.common.constants.StringsGlobal.Error.INV_INPUT;
import static com.example.authenticationService.common.constants.StringsGlobal.Error.INV_STRING;

public enum YesOrNoEnum {
    YES("Yes", true, 1),
    NO("No", false, 0);

    private final String label;
    private final boolean bool;
    private final int num;

    YesOrNoEnum(String label, boolean bool, int num) {
        this.label = label;
        this.bool = bool;
        this.num = num;
    }

    public String getLabel() { return label; }
    public boolean toBoolean() { return bool; }
    public int toInt() { return num; }

    public static YesOrNoEnum from(Object v) {
        if (v == null) return null;
        if (v instanceof YesOrNoEnum e) return e;
        if (v instanceof Boolean b) return b ? YES : NO;
        if (v instanceof Number n) return n.intValue() == 1 ? YES : NO;

        String s = v.toString().trim().toLowerCase();
        return switch (s) {
            case "yes", "y", "true", "1" -> YES;
            case "no",  "n", "false","0" -> NO;
            default -> throw new IllegalArgumentException(INV_INPUT + ": " + v);
        };
    }
}

