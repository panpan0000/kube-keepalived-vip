# Copyright 2015 The Kubernetes Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM quay.io/kubernetes-ingress-controller/debian-base-amd64:0.1

COPY sources.list /etc/apt/sources.list 
#ADD https://mirrors.ustc.edu.cn/repogen/conf/debian-http-4-buster /etc/apt/sources.list

COPY build.sh /build.sh

ENV VERSION 2.0.18
ENV SHA256 b2121760bba368301ed3607caa0a9a2be91bc07d50963a005d04930670428360

RUN clean-install bash

RUN /build.sh
