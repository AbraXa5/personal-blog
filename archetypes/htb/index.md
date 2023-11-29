---
title: "{{ $name := replace .Name "-" " " | title }}{{ $name = replace $name "Htb" "HTB" }}{{ $name }}"
draft: true
categories: ["HTB", ""]
tags:
    -
date: {{ .Date }}
summary: ""
---

# {{ $name }}
