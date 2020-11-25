package com.mixiyihao.security.tool;

import java.util.List;

/**
    @version 1.0.0
 SQL 注入中修复的方式一般都是通过预编译或者参数化查询， 排序使用白名单方式防止。

    但是在有些场景中，由于开发中判断条件复杂，为了简写SQL语句可能会用到拼接，从而导致了SQL注入，或者可能采用预编译并且使用了前端控制
 ORDER BY 等排序查询造成的SQL 注入
    1. 如果是数字型的进行强转修复
    2. 如果是字符型的可以使用下面
    3. order by 注入使用白名单修复

 */
public interface SQLInjectionProtect {



    /**
     *
     优点： 转义' " \  这种可以防止SQL注入，字符型， 而且更快，更准
     缺点： 无法防御order by 注入，整形注入，宽字节注入(需要配合mysql gbk编码)
     转义特殊字符比如将, 此种只能过滤字符型，碰到order by 这种无法防御，需使用白名单，还有就是整形的也无法，需强转类型
      '  ->  \'
      " -> \"
      \ ->  \\

     * @param params
     * @return 返回修复之后的参数
     */
    public String filterIllegalCharacterToParaphrased(String params);

    /**
     * 过滤特殊字符转化为空进行修复 ，与filterSpecialCharactersToParaphrased 方法类似，个人推荐filterSpecialCharactersToParaphrased

     * @param params
     * @return
     */
    public String filterSpecialCharactersToEmpty(String params);

    /**
     * 判断是包含特殊字符， 通过正则判断是否特殊字符
     * @param params
     * @return
     */
    public boolean checkSafeByIllegalCharacters(String params);

    /**
     * 如果一个数组中都是数字，并且穿的是字符串类型， 那么就对数组进行强转检测，防止注入
     * @param params
     * @return true 安全，false不安全
     */
    public boolean checkSafeByIntegerArrayHasIllegalString(String[] params);

    /**
     * order by 类型使用白名单验证，因为预编译对order by 排序无法防御，所以需要进行白名单设置
     * @param orderby 字段值
     * @param whiteList 白名单列表
     * @return true在白名单，false 不在白名单
     */
    public boolean checkSafeByOrderBy(String orderby, List<String> whiteList);

}
