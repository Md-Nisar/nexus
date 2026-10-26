// @ts-check
const eslint = require("@eslint/js");
const { defineConfig } = require("eslint/config");
const tseslint = require("typescript-eslint");
const angular = require("angular-eslint");

module.exports = defineConfig([
  {
    files: ["**/*.ts"],
    extends: [
      eslint.configs.recommended,
      tseslint.configs.recommended,
      tseslint.configs.stylistic,
      angular.configs.tsRecommended,
    ],
    processor: angular.processInlineTemplates,
    rules: {
      "@angular-eslint/directive-selector": [
        "error",
        {
          type: "attribute",
          prefix: ["nx", "app"],
          style: "camelCase",
        },
      ],
      "@angular-eslint/component-selector": [
        "error",
        {
          type: "element",
          prefix: ["nx", "app"],
          style: "kebab-case",
        },
      ],
      "@typescript-eslint/no-explicit-any": "error",
      "no-console": "error",
    },
  },
  {
    files: ["src/app/core/logging/logger.service.ts", "src/main.ts"],
    rules: {
      "no-console": "off",
    },
  },
  {
    files: ["src/app/**/*.ts"],
    rules: {
      "no-restricted-syntax": [
        "error",
        {
          selector:
            "MemberExpression[property.name=/^(innerHTML|outerHTML|insertAdjacentHTML|createContextualFragment)$/i]",
          message: "HTML sinks are forbidden (RC-62.1). Bind text, or add a typed component.",
        },
        {
          selector:
            "MemberExpression[computed=true][property.value=/^(innerHTML|outerHTML|insertAdjacentHTML|createContextualFragment)$/i]",
          message: "HTML sinks are forbidden (RC-62.1). Bind text, or add a typed component.",
        },
        {
          selector: "Property[key.name=/^(innerHTML|outerHTML)$/i]",
          message: "HTML sinks are forbidden (RC-62.1). Bind text, or add a typed component.",
        },
        {
          selector: "MemberExpression[computed=true][property.type='TemplateLiteral'][property.quasis.0.value.cooked=/^(innerHTML|outerHTML|insertAdjacentHTML|createContextualFragment)$/i]",
          message: "HTML sinks are forbidden (RC-62.1). Bind text, or add a typed component.",
        },
        {
          selector: "Property[key.value=/^(innerHTML|outerHTML)$/i]",
          message: "HTML sinks are forbidden (RC-62.1). Bind text, or add a typed component.",
        },
        {
          selector: "Property[computed=true][key.type='TemplateLiteral'][key.quasis.0.value.cooked=/^(innerHTML|outerHTML)$/i]",
          message: "HTML sinks are forbidden (RC-62.1). Bind text, or add a typed component.",
        },
        {
          selector: "MemberExpression[object.name='document'][property.name=/^write(ln)?$/]",
          message: "document.write is forbidden (RC-62.1), including aliases.",
        },
        {
          selector: "MemberExpression[computed=true][object.name='document'][property.value=/^write(ln)?$/]",
          message: "document.write is forbidden (RC-62.1).",
        },
        {
          selector: "MemberExpression[object.property.name='document'][property.name=/^write(ln)?$/]",
          message: "document.write is forbidden (RC-62.1).",
        },
        {
          selector: "MemberExpression[property.name='eval']",
          message: "eval is forbidden (RC-62.1), including window.eval.",
        },
        {
          selector: "VariableDeclarator[init.name='document']",
          message: "Do not alias document (RC-62.1); alias bypasses the document.write ban.",
        },
        {
          selector: "Identifier[name=/^bypassSecurityTrust/]",
          message: "bypassSecurityTrust* is forbidden (RC-62.1), including aliases and destructuring.",
        },
        {
          selector: "MemberExpression[computed=true][property.value=/^bypassSecurityTrust/]",
          message: "bypassSecurityTrust* is forbidden (RC-62.1).",
        },
      ],
      "no-eval": "error",
      "no-new-func": "error",
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: ["@angular/material", "@angular/material/*", "@angular/cdk", "@angular/cdk/*"],
              message: "Import Material/CDK only inside src/app/shared/ui (ADR-0004).",
            },
          ],
        },
      ],
    },
  },
  {
    // Flat config replaces rule options per file, so the Material/CDK pattern is repeated here.
    files: ["src/app/features/**/*.ts"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: ["@angular/material", "@angular/material/*", "@angular/cdk", "@angular/cdk/*"],
              message: "Import Material/CDK only inside src/app/shared/ui (ADR-0004).",
            },
          ],
          paths: [
            {
              name: "@angular/platform-browser",
              importNames: ["DomSanitizer"],
              message: "DomSanitizer is forbidden in features (RC-62.1). Bind text, or add a typed component.",
            },
          ],
        },
      ],
    },
  },
  {
    files: ["src/app/shared/ui/**/*.ts"],
    rules: {
      "no-restricted-imports": "off",
    },
  },
  {
    files: ["**/*.html"],
    extends: [
      angular.configs.templateRecommended,
      angular.configs.templateAccessibility,
    ],
    rules: {
      "no-restricted-syntax": [
        "error",
        {
          selector: "BoundAttribute[name=/^(innerHTML|outerHTML)$/i]",
          message: "HTML sinks are forbidden (RC-62.1). Bind text, or add a typed component.",
        },
      ],
    },
  },
]);
