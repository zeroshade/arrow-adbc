/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;

namespace Apache.Arrow.Adbc.Drivers.Databricks
{
    public class DatabricksException : AdbcException
    {
        private string? _sqlState;
        private int _nativeError;

        public DatabricksException()
        {
        }

        public DatabricksException(string message) : base(message)
        {
        }

        public DatabricksException(string message, AdbcStatusCode statusCode) : base(message, statusCode)
        {
        }

        public DatabricksException(string message, Exception innerException) : base(message, innerException)
        {
        }

        public DatabricksException(string message, AdbcStatusCode statusCode, Exception innerException) : base(message, statusCode, innerException)
        {
        }

        public override string? SqlState
        {
            get { return _sqlState; }
        }

        public override int NativeError
        {
            get { return _nativeError; }
        }

        internal DatabricksException SetSqlState(string sqlState)
        {
            _sqlState = sqlState;
            return this;
        }

        internal DatabricksException SetNativeError(int nativeError)
        {
            _nativeError = nativeError;
            return this;
        }
    }
}
