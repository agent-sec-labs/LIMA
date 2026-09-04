import React, { useState } from "react";
import { Alert, App as AntApp, Button, Form, Input, Modal, Space, Typography } from "antd";
import { useOptionalAuth } from "@/shared/auth/AuthContext";
import { UnauthorizedError } from "@/shared/api/client";

/** 顶栏登录入口：Modal 表单走 AuthContext.signIn；登录态仅持 JWT 于 localStorage。 */

interface LoginFields {
  username: string;
  password: string;
  tenant_id?: string;
}

export function AuthBar(): React.JSX.Element | null {
  const auth = useOptionalAuth();
  const { message } = AntApp.useApp();
  const [open, setOpen] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [form] = Form.useForm<LoginFields>();

  // 无 Provider（纯组件测试）时整条隐藏，不强制依赖。
  if (auth === null) return null;

  const submit = async (): Promise<void> => {
    try {
      const values = await form.validateFields();
      setBusy(true);
      setError("");
      await auth.signIn(values.username, values.password, values.tenant_id ?? "");
      setOpen(false);
      form.resetFields();
      void message.success("登录成功");
    } catch (exc) {
      if (exc instanceof UnauthorizedError) {
        setError("用户名或密码不正确。");
      } else if (exc instanceof Error && exc.message !== "Validation failed.") {
        setError(exc.message);
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <Space size="middle">
      {auth.token === "" ? (
        <Button type="primary" onClick={() => setOpen(true)}>
          登录
        </Button>
      ) : (
        <>
          <Typography.Text type="secondary">已登录</Typography.Text>
          <Button
            onClick={() => {
              auth.signOut();
              void message.info("已退出登录");
            }}
          >
            退出
          </Button>
        </>
      )}
      <Modal
        title="登录 LIMA"
        open={open}
        onCancel={() => setOpen(false)}
        onOk={() => void submit()}
        okText="确认登录"
        cancelText="取消"
        confirmLoading={busy}
        destroyOnClose
      >
        {error !== "" && <Alert type="error" showIcon message={error} style={{ marginBottom: 12 }} />}
        <Form form={form} layout="vertical" requiredMark={false}>
          <Form.Item
            name="username"
            label="用户名"
            rules={[{ required: true, message: "请输入用户名" }]}
          >
            <Input autoComplete="username" />
          </Form.Item>
          <Form.Item
            name="password"
            label="密码"
            rules={[{ required: true, message: "请输入密码" }]}
          >
            <Input.Password autoComplete="current-password" />
          </Form.Item>
          <Form.Item name="tenant_id" label="租户（可选，管理员多租户场景）">
            <Input autoComplete="off" placeholder="default" />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  );
}
