package com.example.authenticationService.common.enums;

public enum StatusEnum {
    ACTIVE("Active"),
    INACTIVE("Inactive"),
    LOCKED("Locked"),
    DISABLED("Disabled"),
    PENDING("Pending"),
    DELETED("Deleted");

    private final String label;

    StatusEnum(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}
