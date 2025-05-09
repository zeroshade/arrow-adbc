/**
 * <auto-generated>
 * Autogenerated by Thrift Compiler (0.21.0)
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 * </auto-generated>
 */
using System;

// targeting netstandard 2.x
#if(! NETSTANDARD2_0_OR_GREATER && ! NET6_0_OR_GREATER && ! NET472_OR_GREATER)
#error Unexpected target platform. See 'thrift --help' for details.
#endif

#pragma warning disable IDE0079  // remove unnecessary pragmas
#pragma warning disable IDE0017  // object init can be simplified
#pragma warning disable IDE0028  // collection init can be simplified
#pragma warning disable IDE1006  // parts of the code use IDL spelling
#pragma warning disable CA1822   // empty DeepCopy() methods still non-static
#pragma warning disable CS0618   // silence our own deprecation warnings
#pragma warning disable IDE0083  // pattern matching "that is not SomeType" requires net5.0 but we still support earlier versions

namespace Apache.Hive.Service.Rpc.Thrift
{
  internal enum TTypeId
  {
    BOOLEAN_TYPE = 0,
    TINYINT_TYPE = 1,
    SMALLINT_TYPE = 2,
    INT_TYPE = 3,
    BIGINT_TYPE = 4,
    FLOAT_TYPE = 5,
    DOUBLE_TYPE = 6,
    STRING_TYPE = 7,
    TIMESTAMP_TYPE = 8,
    BINARY_TYPE = 9,
    ARRAY_TYPE = 10,
    MAP_TYPE = 11,
    STRUCT_TYPE = 12,
    UNION_TYPE = 13,
    USER_DEFINED_TYPE = 14,
    DECIMAL_TYPE = 15,
    NULL_TYPE = 16,
    DATE_TYPE = 17,
    VARCHAR_TYPE = 18,
    CHAR_TYPE = 19,
    INTERVAL_YEAR_MONTH_TYPE = 20,
    INTERVAL_DAY_TIME_TYPE = 21,
    TIMESTAMPLOCALTZ_TYPE = 22,
  }
}
