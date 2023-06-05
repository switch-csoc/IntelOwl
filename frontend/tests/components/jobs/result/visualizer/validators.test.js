const {
  validateLevel,
} = require("../../../../../src/components/jobs/result/visualizer/validators");

describe("visualizer data validation", () => {
  test("Validate only required fields (one element for each component type) and check validation is recursive", () => {
    const validatedLevel = validateLevel({
      level: 0,
      elements: {
        type: "horizontal_list",
        values: [
          {},
          { type: "base" },
          { type: "bool", disable: true },
          { type: "title", title: { type: "base" }, value: { type: "base" } },
          { type: "horizontal_list", value: [] },
          { type: "vertical_list", name: { type: "base" }, value: [] },
        ],
      },
    });
    expect(validatedLevel).toStrictEqual({
      level: 0,
      elements: {
        alignment: "around",
        disable: false,
        size: "col-auto",
        type: "horizontal_list",
        values: [
          {
            alignment: "around",
            bold: false,
            color: "bg-undefined",
            disable: false,
            icon: undefined,
            italic: false,
            link: undefined,
            size: "col-auto",
            type: "base",
            value: undefined,
          },
          {
            alignment: "around",
            bold: false,
            color: "bg-undefined",
            disable: false,
            icon: undefined,
            italic: false,
            link: undefined,
            size: "col-auto",
            type: "base",
            value: undefined,
          },
          {
            activeColor: "danger",
            alignment: "around",
            disable: true,
            icon: undefined,
            italic: false,
            link: undefined,
            size: "col-auto",
            type: "bool",
            value: undefined,
          },
          {
            alignment: "around",
            disable: false,
            size: "col-auto",
            title: {
              alignment: "around",
              bold: false,
              color: "bg-undefined",
              disable: false,
              icon: undefined,
              italic: false,
              link: undefined,
              size: "col-auto",
              type: "base",
              value: undefined,
            },
            type: "title",
            value: {
              alignment: "around",
              bold: false,
              color: "bg-undefined",
              disable: false,
              icon: undefined,
              italic: false,
              link: undefined,
              size: "col-auto",
              type: "base",
              value: undefined,
            },
          },
          {
            alignment: "around",
            disable: false,
            size: "col-auto",
            type: "horizontal_list",
            values: undefined,
          },
          {
            alignment: "around",
            disable: false,
            name: {
              alignment: "around",
              bold: false,
              color: "bg-undefined",
              disable: false,
              icon: undefined,
              italic: false,
              link: undefined,
              size: "col-auto",
              type: "base",
              value: undefined,
            },
            size: "col-auto",
            startOpen: false,
            type: "vertical_list",
            values: undefined,
          },
        ],
      },
    });
  });

  test("Validate all fields (one component for each type)", () => {
    const validatedLevel = validateLevel({
      level: 0,
      elements: {
        type: "horizontal_list",
        values: [
          {
            type: "base",
            value: "placeholder",
            icon: "it",
            color: "success",
            link: "https://google.com",
            bold: true,
            italic: true,
            disable: false,
            size: "1",
            alignment: "start",
          },
          {
            type: "bool",
            value: "phishing",
            icon: "hook",
            italic: true,
            link: "https://google.com",
            color: "danger",
            disable: true,
            size: "2",
            alignment: "end",
          },
          {
            type: "title",
            title: {
              type: "base",
              value: "virus total",
              icon: "virusTotal",
              color: "transparent",
              link: "https://www.virustotal.com",
              bold: true,
              italic: true,
              disable: false,
              size: "1",
              alignment: "center",
            },
            value: {
              type: "base",
              value: "hits: 0%",
              icon: "it",
              color: "success",
              link: "https://google.com",
              bold: true,
              italic: true,
              disable: false,
              size: "1",
              alignment: "start",
            },
            disable: true,
            size: "3",
            alignment: "around",
          },
          // no need to check horizontal_list, this is an horizontal list
          {
            type: "vertical_list",
            name: {
              type: "base",
              value: "vlist title",
              icon: "fire",
              color: "danger",
              link: "https://google.com",
              bold: true,
              italic: true,
              disable: false,
              size: "1",
              alignment: "start",
            },
            values: [
              {
                type: "base",
                value: "suspicious match",
                icon: "ft",
                color: "warning",
                link: "https://google.com",
                bold: true,
                italic: true,
                disable: false,
                size: "1",
                alignment: "start",
              },
              {
                type: "horizontal_list",
                values: [
                  {
                    type: "base",
                    value: "2nd rule matches: ",
                    color: "primary",
                    bold: true,
                    italic: true,
                    disable: false,
                  },
                  {
                    type: "base",
                    value: "match 1",
                    link: "https://google.com",
                    color: "primary",
                    bold: true,
                    italic: true,
                    disable: false,
                  },
                  {
                    type: "base",
                    value: ",",
                    color: "primary",
                    bold: false,
                    italic: false,
                    disable: false,
                  },
                  {
                    type: "base",
                    value: "match 2",
                    link: "https://google.com",
                    ccolor: "primary",
                    bold: true,
                    italic: true,
                    disable: false,
                  },
                ],
              },
            ],
          },
        ],
      },
    });
    expect(validatedLevel).toStrictEqual({
      elements: {
        alignment: "around",
        disable: false,
        size: "col-auto",
        type: "horizontal_list",
        values: [
          {
            alignment: "start",
            bold: true,
            color: "bg-success",
            disable: false,
            icon: "it",
            italic: true,
            link: "https://google.com",
            size: "col-1",
            type: "base",
            value: "placeholder",
          },
          {
            activeColor: "danger",
            alignment: "end",
            disable: true,
            icon: "hook",
            italic: true,
            link: "https://google.com",
            size: "col-2",
            type: "bool",
            value: "phishing",
          },
          {
            type: "title",
            alignment: "around",
            disable: true,
            size: "col-3",
            title: {
              alignment: "center",
              bold: true,
              color: "bg-undefined",
              disable: false,
              icon: "virusTotal",
              italic: true,
              link: "https://www.virustotal.com",
              size: "col-1",
              type: "base",
              value: "virus total",
            },
            value: {
              alignment: "start",
              bold: true,
              color: "bg-success",
              disable: false,
              icon: "it",
              italic: true,
              link: "https://google.com",
              size: "col-1",
              type: "base",
              value: "hits: 0%",
            },
          },
          {
            type: "vertical_list",
            alignment: "around",
            disable: false,
            name: {
              alignment: "start",
              bold: true,
              color: "bg-danger",
              disable: false,
              icon: "fire",
              italic: true,
              link: "https://google.com",
              size: "col-1",
              type: "base",
              value: "vlist title",
            },
            size: "col-auto",
            startOpen: false,
            values: [
              {
                alignment: "start",
                bold: true,
                color: "bg-warning",
                disable: false,
                icon: "ft",
                italic: true,
                link: "https://google.com",
                size: "col-1",
                type: "base",
                value: "suspicious match",
              },
              {
                alignment: "around",
                disable: false,
                size: "col-auto",
                type: "horizontal_list",
                values: [
                  {
                    alignment: "around",
                    bold: true,
                    color: "bg-primary",
                    disable: false,
                    icon: undefined,
                    italic: true,
                    link: undefined,
                    size: "col-auto",
                    type: "base",
                    value: "2nd rule matches: ",
                  },
                  {
                    alignment: "around",
                    bold: true,
                    color: "bg-primary",
                    disable: false,
                    icon: undefined,
                    italic: true,
                    link: "https://google.com",
                    size: "col-auto",
                    type: "base",
                    value: "match 1",
                  },
                  {
                    alignment: "around",
                    bold: false,
                    color: "bg-primary",
                    disable: false,
                    icon: undefined,
                    italic: false,
                    link: undefined,
                    size: "col-auto",
                    type: "base",
                    value: ",",
                  },
                  {
                    alignment: "around",
                    bold: true,
                    color: "bg-undefined",
                    disable: false,
                    icon: undefined,
                    italic: true,
                    link: "https://google.com",
                    size: "col-auto",
                    type: "base",
                    value: "match 2",
                  },
                ],
              },
            ],
          },
        ],
      },
      level: 0,
    });
  });

  test("Validate invalid params (one for each type)", () => {
    const validatedLevel = validateLevel({
      level: 0,
      elements: {
        type: "horizontal_list",
        values: [
          {
            type: "not existing type",
            value: "placeholder",
            icon: "invalid icon",
            color: "#ff0000",
            link: "https://google.com",
            bold: "yes it's bold!",
            italic: "yes it's italic!",
            disable: "yes it's disabled",
            size: "120",
            alignment: "start",
          },
        ],
      },
    });
    expect(validatedLevel).toStrictEqual({
      elements: {
        alignment: "around",
        disable: false,
        size: "col-auto",
        type: "horizontal_list",
        values: [
          {
            alignment: "start",
            bold: true,
            color: "bg-undefined",
            disable: true,
            icon: "invalid icon",
            italic: true,
            link: "https://google.com",
            size: "col-auto",
            type: "base",
            value: "placeholder",
          },
        ],
      },
      level: 0,
    });
  });
});
