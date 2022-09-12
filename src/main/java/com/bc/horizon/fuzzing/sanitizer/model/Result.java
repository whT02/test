package com.bc.horizon.fuzzing.sanitizer.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * <p>DESC: </p >
 * <p>DATE: 2022/6/27 0027</p >
 * <p>VERSION:</p >
 * <p>@AUTHOR: DengC</p >
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder(toBuilder = true)
public class Result {
    /**
     * 是否需要记录  true=需要 false=不需要
     */
    private Boolean needRecord;

    /**
     * 异常id
     */
    private String exceptionId;

    /**
     * 异常名称
     */
    private String exceptionName;

    /**
     * 异常描述
     */
    private String exceptionDesc;

    /**
     * 类名称
     */
    private String exceptionClass;

    /**
     * 目标方法
     */
    private String exceptionMethod;

    /**
     * 目标行数
     */
    private Integer methodLine;

    /**
     * 请求参数
     */
    private String requestParam;

    /**
     * 堆栈信息
     */
    private String stackInfo;


}
