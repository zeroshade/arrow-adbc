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
using Apache.Arrow.Adbc.Drivers.Apache;
using Apache.Arrow.Adbc.Tracing;

namespace Apache.Arrow.Adbc.Drivers.Databricks
{
    /// <summary>
    /// Base class for Databricks readers that handles common functionality. Handles the operation status poller.
    /// </summary>
    internal abstract class BaseDatabricksReader : TracingReader
    {
        protected DatabricksStatement statement;
        protected readonly Schema schema;
        protected readonly bool isLz4Compressed;
        protected DatabricksOperationStatusPoller? operationStatusPoller;
        protected bool hasNoMoreRows = false;
        private bool isDisposed;

        protected BaseDatabricksReader(DatabricksStatement statement, Schema schema, bool isLz4Compressed)
            : base(statement)
        {
            this.schema = schema;
            this.isLz4Compressed = isLz4Compressed;
            this.statement = statement;
            if (statement.DirectResults?.ResultSet != null && !statement.DirectResults.ResultSet.HasMoreRows)
            {
                return;
            }
            operationStatusPoller = new DatabricksOperationStatusPoller(statement);
            operationStatusPoller.Start();
        }

        public override Schema Schema { get { return schema; } }

        protected void StopOperationStatusPoller()
        {
            operationStatusPoller?.Stop();
        }

        protected override void Dispose(bool disposing)
        {
            if (!isDisposed)
            {
                if (disposing)
                {
                    DisposeOperationStatusPoller();
                    DisposeResources();
                }
                isDisposed = true;
            }

            base.Dispose(disposing);
        }

        protected virtual void DisposeResources()
        {
        }

        protected void DisposeOperationStatusPoller()
        {
            if (operationStatusPoller != null)
            {
                operationStatusPoller.Stop();
                operationStatusPoller.Dispose();
                operationStatusPoller = null;
            }
        }

        protected void ThrowIfDisposed()
        {
            if (isDisposed)
            {
                throw new ObjectDisposedException(GetType().Name);
            }
        }

        public override string AssemblyName => DatabricksConnection.s_assemblyName;

        public override string AssemblyVersion => DatabricksConnection.s_assemblyVersion;
    }
}
