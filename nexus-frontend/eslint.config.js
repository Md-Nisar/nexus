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
          selector: "MemberExpression[property.name=/^(innerHTML|outerHTML)$/i]",
          message: "HTML sinks are forbidden (RC-62.1). Bind text, or add a typed component.",
        },
        {
          selector: "CallExpression[callee.property.name=/^bypassSecurityTrust/]",
          message: "bypassSecurityTrust* is forbidden (RC-62.1).",
        },
      ],
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
    // Material usage that predates the boundary rule; migrate to shared/ui wrappers, then delete.
    files: [
      "src/app/shared/ui/**/*.ts",
      "src/app/features/auth/registration-form/registration-form.component.ts",
      "src/app/features/auth/verification-landing/verification-landing.component.ts",
      "src/app/features/design-system/design-system-preview.component.ts",
    ],
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
