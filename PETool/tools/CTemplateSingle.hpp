#pragma once

template<class T>
class CTemplateSingle
{
public:
	static T* GetInstance()
	{

		if (NULL == m_inst)
		{
			m_inst = new T;
		}
			
		return m_inst;
	}

	static void DestroyInstance()
	{

		if (NULL != m_inst)
		{
			delete m_inst;
			m_inst = NULL;
		}
	}

private:
	static T* m_inst;

};

template<class T>
T* CTemplateSingle<T>::m_inst = NULL;