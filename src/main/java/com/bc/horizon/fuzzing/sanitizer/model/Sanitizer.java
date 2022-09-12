package com.bc.horizon.fuzzing.sanitizer.model;

import com.bc.horizon.fuzzing.sanitizer.annotation.HookType;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Arrays;
import java.util.List;

/**
 * <p>DESC: </p >
 * <p>DATE: 2022/6/27 0027</p >
 * <p>VERSION:1.0.0</p >
 * <p>@AUTHOR: DengC</p >
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Sanitizer {
    private String targetClass;

    private String targetMethod;

    private List<HookType> type;

    private String handlerClass;

    public Sanitizer(String targetClass, String targetMethod, HookType[] type, String handlerClass) {
        this.targetClass = targetClass;
        this.targetMethod = targetMethod;
        this.type = Arrays.asList(type);
        this.handlerClass = handlerClass;
    }
}
